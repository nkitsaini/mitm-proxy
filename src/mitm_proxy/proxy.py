"""Streaming forwarding HTTP proxy.

Design notes
------------
* Bodies are *never* buffered fully in memory. We open a file per direction
  (`<trace_id>.req`, `<trace_id>.resp`) and write each chunk as we forward it,
  using a tee async-generator. TCP backpressure naturally limits memory usage
  to a single chunk (`CHUNK_SIZE`).
* `auto_decompress=False` on the upstream client: we want bodies to be stored
  exactly as they came off the wire (raw, possibly gzip/br/zstd compressed).
  The original `Content-Encoding` header is preserved end-to-end so clients
  still decompress correctly.
* Hop-by-hop headers (RFC 7230 §6.1) are stripped on both legs. `Content-Length`
  is also stripped because we always use chunked transfer encoding for the
  outbound legs to support unknown-size streaming uniformly.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path
from typing import AsyncIterator

import aiofiles
import aiohttp
from aiohttp import web

from .storage import Headers, Storage

# Errors that mean "the peer (client or upstream) went away mid-stream".
# We absorb these so that we still finalize the capture row instead of
# losing the status code + headers we already received.
_PEER_GONE: tuple[type[BaseException], ...] = (
    ConnectionError,
    ConnectionResetError,
    aiohttp.ClientConnectionError,
    aiohttp.ClientConnectionResetError,
    asyncio.CancelledError,
)

# Hop-by-hop headers (RFC 7230 §6.1) plus Host (auto-set by the client based on
# the upstream URL) plus Content-Length (we re-frame everything as chunked).
HOP_BY_HOP: frozenset[str] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)

# Methods that conventionally cannot carry a body.
BODYLESS_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

CHUNK_SIZE = 64 * 1024


def _filter_headers(items) -> Headers:
    """Return a list of (name, value) pairs with hop-by-hop headers removed.

    Order and duplicates are preserved (important for headers like Set-Cookie).
    Accepts anything yielding (name, value) on .items().
    """
    return [(name, value) for name, value in items.items() if name.lower() not in HOP_BY_HOP]


class Proxy:
    def __init__(
        self,
        *,
        upstream: str,
        storage: Storage,
        bodies_dir: Path,
        verify_tls: bool = True,
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.storage = storage
        self.bodies_dir = Path(bodies_dir)
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        self.verify_tls = verify_tls
        self.session: aiohttp.ClientSession | None = None

    # ---------------------------------------------------------------- lifecycle

    async def on_startup(self, _app: web.Application) -> None:
        connector = aiohttp.TCPConnector(
            limit=200,
            ssl=self.verify_tls,
        )
        # total=None means no overall deadline (long-running streams allowed);
        # sock_read protects against dead upstreams.
        self.session = aiohttp.ClientSession(
            connector=connector,
            auto_decompress=False,
            timeout=aiohttp.ClientTimeout(
                total=None, connect=30, sock_connect=30, sock_read=300
            ),
        )

    async def on_cleanup(self, _app: web.Application) -> None:
        if self.session is not None:
            await self.session.close()
            self.session = None

    # ------------------------------------------------------------------ handler

    async def handle(self, request: web.Request) -> web.StreamResponse:
        assert self.session is not None, "Proxy.on_startup was not called"

        trace_id = uuid.uuid4().hex
        start_ts = time.time()

        req_body_name = f"{trace_id}.req"
        resp_body_name = f"{trace_id}.resp"
        req_body_path = self.bodies_dir / req_body_name
        resp_body_path = self.bodies_dir / resp_body_name

        # Preserve the raw path+query exactly as the client sent it.
        upstream_url = self.upstream + request.path_qs
        client_ip = request.remote or ""
        request_headers = _filter_headers(request.headers)

        # Mutable counters captured by the tee generators.
        request_size = 0
        response_size = 0

        method_has_body = request.method.upper() not in BODYLESS_METHODS

        async def tee_request() -> AsyncIterator[bytes]:
            """Read client body chunks, append to disk, yield onward to upstream."""
            nonlocal request_size
            async with aiofiles.open(req_body_path, "wb") as f:
                async for chunk in request.content.iter_chunked(CHUNK_SIZE):
                    if not chunk:
                        continue
                    request_size += len(chunk)
                    await f.write(chunk)
                    yield chunk

        # Insert a "pending" row immediately so we always have an audit record,
        # even if the upstream call later blows up.
        row_id = await self.storage.insert_pending(
            trace_id=trace_id,
            start_ts=start_ts,
            client_ip=client_ip,
            method=request.method,
            request_url=str(request.url),
            upstream_url=upstream_url,
            request_headers=request_headers,
            request_body_path=req_body_name if method_has_body else None,
        )

        upstream_kwargs: dict = {
            "method": request.method,
            "url": upstream_url,
            "headers": request_headers,
            "allow_redirects": False,
        }
        if method_has_body:
            upstream_kwargs["data"] = tee_request()
            # aiohttp uses chunked encoding automatically when data is an
            # async iterable; setting `chunked=True` makes that explicit.
            upstream_kwargs["chunked"] = True

        try:
            async with self.session.request(**upstream_kwargs) as upstream_resp:
                response_headers = _filter_headers(upstream_resp.headers)
                status_code = upstream_resp.status

                # Build a streaming response back to the client. We force
                # chunked encoding because we don't know the total size yet
                # (and we've stripped Content-Length).
                downstream = web.StreamResponse(
                    status=status_code,
                    headers=response_headers,
                )
                downstream.enable_chunked_encoding()

                # The client may have already gone away by the time we have
                # an upstream response. Track that explicitly so we keep
                # draining upstream (writing to disk) and still finalize the
                # capture instead of crashing.
                downstream_alive = True
                try:
                    await downstream.prepare(request)
                except _PEER_GONE:
                    downstream_alive = False

                async with aiofiles.open(resp_body_path, "wb") as f:
                    async for chunk in upstream_resp.content.iter_chunked(CHUNK_SIZE):
                        if not chunk:
                            continue
                        response_size += len(chunk)
                        await f.write(chunk)
                        if downstream_alive:
                            try:
                                await downstream.write(chunk)
                            except _PEER_GONE:
                                downstream_alive = False

                if downstream_alive:
                    try:
                        await downstream.write_eof()
                    except _PEER_GONE:
                        downstream_alive = False

                end_ts = time.time()
                await self.storage.finalize(
                    row_id,
                    end_ts=end_ts,
                    duration_ms=(end_ts - start_ts) * 1000.0,
                    request_body_size=request_size,
                    status_code=status_code,
                    response_headers=response_headers,
                    response_body_path=resp_body_name,
                    response_body_size=response_size,
                )
                return downstream

        except Exception as exc:  # noqa: BLE001 - we want to record anything
            end_ts = time.time()
            await self.storage.fail(
                row_id,
                end_ts=end_ts,
                duration_ms=(end_ts - start_ts) * 1000.0,
                request_body_size=request_size,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise


def build_app(proxy: Proxy) -> web.Application:
    # client_max_size=0 disables aiohttp's accumulated-body cap. We use
    # `request.content.iter_chunked()` which streams regardless, but the cap
    # would still trip on the total bytes seen if we left it at its 1 MiB
    # default.
    app = web.Application(client_max_size=0)
    app.on_startup.append(proxy.on_startup)
    app.on_cleanup.append(proxy.on_cleanup)
    app.router.add_route("*", "/{tail:.*}", proxy.handle)
    return app
