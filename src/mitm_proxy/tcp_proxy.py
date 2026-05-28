"""Raw asyncio TCP HTTP/1.x forwarding proxy.

Why a second implementation
---------------------------
``proxy.py`` is built on aiohttp, which parses HTTP into an in-memory model
and re-emits it. That's convenient but means upstream sees a number of things
the original client never sent / wouldn't have sent:

  * default headers injected (``User-Agent``, ``Accept-Encoding``)
  * ``Content-Length`` stripped and chunked transfer-encoding forced
  * ``Upgrade`` stripped
  * reason phrase regenerated from aiohttp's table
  * trailers dropped
  * 1xx interim responses (100, 103) consumed silently
  * HTTP/1.0 silently upgraded to HTTP/1.1

This module is a byte-faithful alternative. We parse just enough HTTP/1.x to
find message boundaries (start-line + header block + body framing) and rewrite
exactly two things on the way out:

  1. the request-line ``request-target`` is left as the client sent it (we
     only forward to a single fixed upstream),
  2. the ``Host:`` header value is replaced with the upstream's authority.

Everything else -- header order, casing, whitespace, reason phrase, framing
choice, trailers, ``Upgrade``, ``Connection``, ``Expect``, all of it -- is
passed through verbatim.

Memory model
------------
Per active connection-pair, peak in-process memory is bounded by:

  * ``STREAM_LIMIT`` (64 KiB) per direction for the header / chunk-size line
    buffer (asyncio.StreamReader limit; reads beyond this raise ProtocolError).
  * ``CHUNK_SIZE`` (64 KiB) per direction for body bytes in flight.
  * aiofiles' default thread-pool buffer for the capture tee.

That's on the order of 256 KiB per active client connection, regardless of
body size. No request or response body is ever buffered in full. There is no
in-memory copy of the wire bytes -- we read a chunk, write it to the peer,
write the (decoded, for chunked) payload to the body file, then drop the
reference.

Behavioural notes
-----------------
* HTTP/1.x only. HTTP/2 prior-knowledge connections will parse as malformed
  and the proxy will close them.
* Per-connection 1:1 bridge: one upstream connection for the lifetime of each
  client connection. Keep-alive is mirrored from the client/upstream
  ``Connection`` headers and HTTP version.
* ``Upgrade`` with a ``101 Switching Protocols`` response triggers a raw
  bidirectional byte splice between the two sockets. WebSockets, h2c, etc.
  all tunnel transparently.
* ``Expect: 100-continue`` is handled specially: after forwarding the request
  head we read and forward upstream's interim response(s) before streaming
  the request body, so neither side deadlocks.
* Pipelined requests are accepted but serialized: req2 doesn't start being
  forwarded until req1's response is complete.
* Close-delimited responses (HTTP/1.0 style; neither ``Content-Length`` nor
  ``Transfer-Encoding``) are forwarded by reading-until-EOF; this kind of
  response forces the connection to close after.
"""

from __future__ import annotations

import asyncio
import socket
import ssl as ssl_lib
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import aiofiles

from .storage import Headers, Storage

# 64 KiB: the default chunk size everywhere; also asyncio's default StreamReader
# buffer limit. Using the same value for header parsing and body forwarding keeps
# per-connection memory predictable.
STREAM_LIMIT = 64 * 1024
CHUNK_SIZE = 64 * 1024

# 10 minutes per individual read. There is intentionally no overall deadline:
# long polls, server-sent events, and slow streams should all just work.
IDLE_READ_TIMEOUT = 600.0

# How long to wait for the upstream TCP/TLS handshake at the start of a new
# client connection. After that we hand off to IDLE_READ_TIMEOUT.
UPSTREAM_CONNECT_TIMEOUT = 30.0


class ProtocolError(Exception):
    """Malformed HTTP framing from one of the peers."""


# =========================================================== header parsing


def _parse_header_block(block: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    """Split a header block (without the trailing CRLFCRLF) into start-line + headers.

    Preserves the original bytes for header names and values; does no case
    normalization. Supports obsolete line-folding (per RFC 7230 §3.2.4) by
    appending folded lines to the preceding value.
    """
    lines = block.split(b"\r\n")
    if not lines:
        raise ProtocolError("Empty header block")
    start_line = lines[0]
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            if not headers:
                raise ProtocolError("Header continuation with no preceding header")
            name, value = headers[-1]
            headers[-1] = (name, value + b" " + line.lstrip())
            continue
        colon = line.find(b":")
        if colon <= 0:
            raise ProtocolError(f"Malformed header line: {line!r}")
        name = line[:colon]
        value = line[colon + 1 :].lstrip(b" \t")
        headers.append((name, value))
    return start_line, headers


def _find_header(headers: list[tuple[bytes, bytes]], name: bytes) -> Optional[bytes]:
    name_l = name.lower()
    for n, v in headers:
        if n.lower() == name_l:
            return v
    return None


def _has_token(value: Optional[bytes], token: bytes) -> bool:
    """Case-insensitive token search in a comma-separated header value."""
    if value is None:
        return False
    token_l = token.lower()
    return any(p.strip().lower() == token_l for p in value.split(b","))


def _parse_request_line(line: bytes) -> tuple[bytes, bytes, bytes]:
    parts = line.split(b" ")
    if len(parts) != 3:
        raise ProtocolError(f"Malformed request line: {line!r}")
    return parts[0], parts[1], parts[2]


def _parse_status_line(line: bytes) -> tuple[bytes, int, bytes]:
    parts = line.split(b" ", 2)
    if len(parts) < 2:
        raise ProtocolError(f"Malformed status line: {line!r}")
    try:
        status = int(parts[1])
    except ValueError as e:
        raise ProtocolError(f"Bad status code: {parts[1]!r}") from e
    reason = parts[2] if len(parts) > 2 else b""
    return parts[0], status, reason


def _serialize_head(start_line: bytes, headers: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray(start_line)
    out += b"\r\n"
    for n, v in headers:
        out += n
        out += b": "
        out += v
        out += b"\r\n"
    out += b"\r\n"
    return bytes(out)


def _decode_for_storage(headers: list[tuple[bytes, bytes]]) -> Headers:
    # Header field-values are formally ISO-8859-1 per RFC 7230; latin-1 is a
    # lossless 1:1 byte->str mapping so storage round-trips cleanly.
    return [
        (n.decode("ascii", errors="replace"), v.decode("latin-1", errors="replace"))
        for n, v in headers
    ]


def _rewrite_host(
    headers: list[tuple[bytes, bytes]], new_host: bytes
) -> list[tuple[bytes, bytes]]:
    """Replace the first ``Host`` header in-place. If the client didn't send one
    (legal under HTTP/1.0), insert one at the end so upstream can route."""
    out: list[tuple[bytes, bytes]] = []
    replaced = False
    for n, v in headers:
        if not replaced and n.lower() == b"host":
            out.append((n, new_host))
            replaced = True
        else:
            out.append((n, v))
    if not replaced:
        out.append((b"Host", new_host))
    return out


def _parse_int(value: Optional[bytes]) -> int:
    if value is None:
        raise ProtocolError("Missing integer header value")
    try:
        return int(value.strip())
    except ValueError as e:
        raise ProtocolError(f"Not an integer: {value!r}") from e


def _wants_close(headers: list[tuple[bytes, bytes]], version: bytes) -> bool:
    """Apply RFC 7230 §6.3 connection persistence rules."""
    conn = _find_header(headers, b"Connection")
    if conn is not None:
        if _has_token(conn, b"close"):
            return True
        if _has_token(conn, b"keep-alive"):
            return False
    return version != b"HTTP/1.1"


# =========================================================== stream helpers


async def _read_head(
    reader: asyncio.StreamReader, *, timeout: float = IDLE_READ_TIMEOUT
) -> bytes:
    """Read up to (but not including) the CRLFCRLF terminator of an HTTP message head."""
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    except asyncio.LimitOverrunError as e:
        raise ProtocolError(f"Header block exceeds {STREAM_LIMIT} bytes") from e
    return data[:-4]


async def _read_line(
    reader: asyncio.StreamReader, *, timeout: float = IDLE_READ_TIMEOUT
) -> bytes:
    try:
        return await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=timeout)
    except asyncio.LimitOverrunError as e:
        raise ProtocolError(f"Line exceeds {STREAM_LIMIT} bytes") from e


async def _read_exact(
    reader: asyncio.StreamReader, n: int, *, timeout: float = IDLE_READ_TIMEOUT
) -> bytes:
    return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)


async def _read_some(
    reader: asyncio.StreamReader, n: int, *, timeout: float = IDLE_READ_TIMEOUT
) -> bytes:
    return await asyncio.wait_for(reader.read(n), timeout=timeout)


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


def _safe_abort(writer: Optional[asyncio.StreamWriter]) -> None:
    """Abort the underlying transport (drop pending writes, close immediately).

    Used on error paths so the peer doesn't mistake a truncated stream for a
    successful, short response. Note: asyncio's ``abort()`` schedules an
    immediate close but doesn't guarantee a TCP RST -- the kernel still sends
    FIN unless ``SO_LINGER=(1, 0)`` is set. The behavioral win is that any
    bytes we hadn't yet flushed are dropped, so we don't deliver a
    half-finished response.
    """
    if writer is None:
        return
    try:
        writer.transport.abort()
    except Exception:  # noqa: BLE001 - abort in error paths must never raise
        pass


def _configure_socket(writer: asyncio.StreamWriter) -> None:
    """Apply TCP options we want on every connection leg.

    * ``TCP_NODELAY``: disable Nagle so small writes (size lines, chunked
      framing, SSE events) aren't held in the kernel for up to 200 ms.
    * ``SO_KEEPALIVE``: let the kernel detect a silently-dead peer (router
      eviction, half-open connection) on its own. Doesn't traverse the proxy
      -- each leg independently watches its own peer.
    """
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except (OSError, AttributeError):
        pass


def _add_xff_header(
    headers: list[tuple[bytes, bytes]], client_ip: str
) -> list[tuple[bytes, bytes]]:
    """Append ``client_ip`` to the ``X-Forwarded-For`` header, extending an
    existing one if present. Returns a new list; does not mutate input."""
    if not client_ip:
        return headers
    ip_bytes = client_ip.encode("ascii")
    out: list[tuple[bytes, bytes]] = []
    extended = False
    for n, v in headers:
        if not extended and n.lower() == b"x-forwarded-for":
            out.append((n, v + b", " + ip_bytes))
            extended = True
        else:
            out.append((n, v))
    if not extended:
        out.append((b"X-Forwarded-For", ip_bytes))
    return out


# =========================================================== body forwarding


# aiofiles' file-like object; we only call .write() on it.
BodyTee = Optional[Any]


async def _forward_content_length(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tee: BodyTee,
    length: int,
    *,
    timeout: float = IDLE_READ_TIMEOUT,
    on_progress: Optional[Callable[[int], None]] = None,
) -> int:
    remaining = length
    sent = 0
    while remaining > 0:
        chunk = await _read_some(reader, min(CHUNK_SIZE, remaining), timeout=timeout)
        if not chunk:
            raise ProtocolError("EOF before Content-Length body fully read")
        writer.write(chunk)
        if tee is not None:
            await tee.write(chunk)
        sent += len(chunk)
        remaining -= len(chunk)
        if on_progress is not None:
            on_progress(sent)
        await writer.drain()
    return length


async def _forward_chunked(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tee: BodyTee,
    *,
    timeout: float = IDLE_READ_TIMEOUT,
    on_progress: Optional[Callable[[int], None]] = None,
) -> int:
    """Forward a Transfer-Encoding: chunked body verbatim.

    The forwarded bytes keep their chunked framing intact (size lines, CRLFs,
    trailers). The tee file receives only the chunk payloads concatenated, so
    the captured body is the decoded content -- matching aiohttp's behavior in
    proxy.py.

    Returns the decoded body size.
    """
    decoded = 0
    while True:
        size_line = await _read_line(reader, timeout=timeout)
        writer.write(size_line)
        size_hex = size_line[:-2].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_hex, 16)
        except ValueError as e:
            raise ProtocolError(f"Bad chunk size: {size_line!r}") from e
        if chunk_size < 0:
            raise ProtocolError(f"Negative chunk size: {chunk_size}")
        if chunk_size == 0:
            while True:
                line = await _read_line(reader, timeout=timeout)
                writer.write(line)
                if line == b"\r\n":
                    break
            await writer.drain()
            return decoded
        remaining = chunk_size
        while remaining > 0:
            chunk = await _read_some(
                reader, min(CHUNK_SIZE, remaining), timeout=timeout
            )
            if not chunk:
                raise ProtocolError("EOF mid chunk payload")
            writer.write(chunk)
            if tee is not None:
                await tee.write(chunk)
            decoded += len(chunk)
            remaining -= len(chunk)
            if on_progress is not None:
                on_progress(decoded)
        crlf = await _read_exact(reader, 2, timeout=timeout)
        if crlf != b"\r\n":
            raise ProtocolError("Missing CRLF after chunk")
        writer.write(crlf)
        await writer.drain()


async def _forward_until_close(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tee: BodyTee,
    *,
    timeout: float = IDLE_READ_TIMEOUT,
) -> int:
    """Read from reader until EOF, forward all bytes. Used for close-delimited
    responses (no Content-Length, no Transfer-Encoding). Forces connection close
    after, since the message boundary is the connection boundary."""
    total = 0
    while True:
        chunk = await _read_some(reader, CHUNK_SIZE, timeout=timeout)
        if not chunk:
            return total
        writer.write(chunk)
        if tee is not None:
            await tee.write(chunk)
        total += len(chunk)
        await writer.drain()


async def _splice(
    a_reader: asyncio.StreamReader,
    a_writer: asyncio.StreamWriter,
    b_reader: asyncio.StreamReader,
    b_writer: asyncio.StreamWriter,
    *,
    timeout: float = IDLE_READ_TIMEOUT,
) -> None:
    """Bidirectional raw byte forwarding between two endpoints.

    Used after a 101 Switching Protocols response when the connection becomes
    an opaque sub-protocol tunnel (WebSockets, h2c, etc.). Captures nothing
    once we're past 101 -- the bytes aren't HTTP anymore.
    """

    async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await _read_some(src, CHUNK_SIZE, timeout=timeout)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, OSError):
            pass
        finally:
            try:
                dst.write_eof()
            except (OSError, RuntimeError):
                pass

    await asyncio.gather(
        pump(a_reader, b_writer),
        pump(b_reader, a_writer),
        return_exceptions=True,
    )


# ================================================================== proxy


class TCPProxy:
    """Per-connection 1:1 byte-forwarding HTTP proxy."""

    def __init__(
        self,
        *,
        upstream: str,
        storage: Storage,
        bodies_dir: Path,
        verify_tls: bool = True,
        add_xff: bool = False,
        idle_read_timeout: float = IDLE_READ_TIMEOUT,
        upstream_connect_timeout: float = UPSTREAM_CONNECT_TIMEOUT,
    ) -> None:
        parsed = urlsplit(upstream)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"upstream scheme must be http or https, got {parsed.scheme!r}"
            )
        if not parsed.hostname:
            raise ValueError(f"upstream URL missing host: {upstream!r}")
        self.upstream_scheme = parsed.scheme
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_default_port = (
            parsed.scheme == "https" and self.upstream_port == 443
        ) or (parsed.scheme == "http" and self.upstream_port == 80)
        if is_default_port:
            self.upstream_host_header = self.upstream_host.encode("ascii")
        else:
            self.upstream_host_header = (
                f"{self.upstream_host}:{self.upstream_port}".encode("ascii")
            )
        self.storage = storage
        self.bodies_dir = Path(bodies_dir)
        self.bodies_dir.mkdir(parents=True, exist_ok=True)
        self.verify_tls = verify_tls
        self.add_xff = add_xff
        self.idle_read_timeout = idle_read_timeout
        self.upstream_connect_timeout = upstream_connect_timeout
        if parsed.scheme == "https":
            self.ssl_ctx: Optional[ssl_lib.SSLContext] = ssl_lib.create_default_context()
            if not verify_tls:
                self.ssl_ctx.check_hostname = False
                self.ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        else:
            self.ssl_ctx = None

        # Test/introspection hook: called once per accepted connection-pair,
        # after both sockets have been opened and TCP options configured.
        # Receives (client_socket, upstream_socket). Use to assert socket state
        # in tests; don't rely on it in production code.
        self.on_connection_setup: Optional[
            Callable[[socket.socket, socket.socket], None]
        ] = None

    # ------------------------------------------------------------ entry point

    async def handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        client_ip = peer[0] if peer else ""
        upstream_reader: Optional[asyncio.StreamReader] = None
        upstream_writer: Optional[asyncio.StreamWriter] = None
        try:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host=self.upstream_host,
                        port=self.upstream_port,
                        ssl=self.ssl_ctx,
                        server_hostname=(
                            self.upstream_host if self.ssl_ctx is not None else None
                        ),
                        limit=STREAM_LIMIT,
                    ),
                    timeout=self.upstream_connect_timeout,
                )
            except (OSError, asyncio.TimeoutError, ssl_lib.SSLError):
                return

            # Tune both legs: NODELAY for small-write latency, KEEPALIVE for
            # silent-peer detection. Direct client->upstream connections
            # typically have these on; without setting them here, going through
            # the proxy quietly changes wire timing.
            _configure_socket(client_writer)
            _configure_socket(upstream_writer)
            if self.on_connection_setup is not None:
                cs = client_writer.get_extra_info("socket")
                us = upstream_writer.get_extra_info("socket")
                if cs is not None and us is not None:
                    try:
                        self.on_connection_setup(cs, us)
                    except Exception:  # noqa: BLE001 - test hook errors must not crash the proxy
                        pass

            while True:
                keep_alive = await self._serve_one(
                    client_ip,
                    client_reader,
                    client_writer,
                    upstream_reader,
                    upstream_writer,
                )
                if not keep_alive:
                    return
        finally:
            _safe_close(client_writer)
            if upstream_writer is not None:
                _safe_close(upstream_writer)

    # ----------------------------------------------------- one request/response

    async def _serve_one(
        self,
        client_ip: str,
        cr: asyncio.StreamReader,
        cw: asyncio.StreamWriter,
        ur: asyncio.StreamReader,
        uw: asyncio.StreamWriter,
    ) -> bool:
        """Process a single request/response on an existing connection pair.

        Returns True if the pair can serve another request, False if it must
        be torn down.
        """
        # ---------------- parse client's request head ----------------
        try:
            req_head_bytes = await _read_head(cr, timeout=self.idle_read_timeout)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, OSError):
            return False
        except ProtocolError:
            return False

        try:
            req_start, req_headers = _parse_header_block(req_head_bytes)
            method, _target, http_version = _parse_request_line(req_start)
        except ProtocolError:
            return False

        trace_id = uuid.uuid4().hex
        start_ts = time.time()
        req_body_name = f"{trace_id}.req"
        resp_body_name = f"{trace_id}.resp"
        req_body_path = self.bodies_dir / req_body_name
        resp_body_path = self.bodies_dir / resp_body_name

        method_str = method.decode("ascii", errors="replace").upper()
        target_str = _target.decode("latin-1", errors="replace")
        orig_host = _find_header(req_headers, b"Host") or b""

        # Detect framing of the request body.
        req_te = _find_header(req_headers, b"Transfer-Encoding")
        req_cl = _find_header(req_headers, b"Content-Length")
        req_chunked = _has_token(req_te, b"chunked")
        req_has_body = req_chunked or (req_cl is not None and req_cl.strip() != b"0")

        # The single mutation that's always applied: rewrite the Host value.
        rewritten_headers = _rewrite_host(req_headers, self.upstream_host_header)
        # Optional: append/extend X-Forwarded-For so upstream can recover the
        # original client IP. Off by default to keep the "upstream sees what
        # client sent" contract; enable with TCPProxy(add_xff=True).
        if self.add_xff:
            rewritten_headers = _add_xff_header(rewritten_headers, client_ip)

        request_url_str = (
            f"http://{orig_host.decode('latin-1', errors='replace')}{target_str}"
            if orig_host
            else target_str
        )
        upstream_url_str = (
            f"{self.upstream_scheme}://{self.upstream_host_header.decode()}{target_str}"
        )

        row_id = await self.storage.insert_pending(
            trace_id=trace_id,
            start_ts=start_ts,
            client_ip=client_ip,
            method=method_str,
            request_url=request_url_str,
            upstream_url=upstream_url_str,
            request_headers=_decode_for_storage(rewritten_headers),
            request_body_path=req_body_name if req_has_body else None,
        )

        # Mutable so the body-pump task can publish progress out to the row's
        # finalize/fail accounting (which lives in the enclosing scope).
        body_size_ref: list[int] = [0]
        response_body_size = 0
        close_after_response = False

        async def _fail(exc: BaseException) -> None:
            # Abort both sides so we don't deliver a half-finished response that
            # the client might interpret as a successful short body.
            _safe_abort(cw)
            _safe_abort(uw)
            end = time.time()
            await self.storage.fail(
                row_id,
                end_ts=end,
                duration_ms=(end - start_ts) * 1000.0,
                request_body_size=body_size_ref[0],
                error=f"{type(exc).__name__}: {exc}",
            )

        # ---------------- forward request head ----------------
        try:
            uw.write(_serialize_head(req_start, rewritten_headers))
            await uw.drain()
        except (ConnectionError, OSError) as e:
            await _fail(e)
            return False

        # ---------------- concurrent: body upload + response head watcher ----
        # A direct (no-proxy) client/upstream connection lets upstream emit 1xx
        # interim responses (100 Continue, 103 Early Hints) at *any* time -- in
        # particular while the client is still uploading its body, or in response
        # to Expect: 100-continue *before* any body arrives.
        #
        # To preserve that behavior we run the request-body pump and the
        # response-head watcher as concurrent tasks. The watcher forwards every
        # 1xx response to the client as it arrives, and only returns when a
        # final response head (non-1xx, or 101) is received. This also subsumes
        # the Expect: 100-continue case: the body pump blocks reading from the
        # client until the watcher forwards the 100 (which the client was
        # waiting on), at which point the client begins sending the body and
        # the pump unblocks naturally.
        #
        # If upstream produces a final response *before* the body finishes
        # uploading (e.g. 417 Expectation Failed, or a fast 4xx based on
        # headers alone), we cancel the body pump and mark the upstream
        # connection as unsafe to reuse (the incomplete request body remains
        # in upstream's read buffer).

        def _on_body_progress(n: int) -> None:
            body_size_ref[0] = n

        async def _body_pump() -> None:
            if not req_has_body:
                return
            async with aiofiles.open(req_body_path, "wb") as tee:
                if req_chunked:
                    await _forward_chunked(
                        cr, uw, tee,
                        timeout=self.idle_read_timeout,
                        on_progress=_on_body_progress,
                    )
                else:
                    length = _parse_int(req_cl)
                    if length < 0:
                        raise ProtocolError(f"Negative Content-Length: {length}")
                    await _forward_content_length(
                        cr, uw, tee, length,
                        timeout=self.idle_read_timeout,
                        on_progress=_on_body_progress,
                    )

        body_task = asyncio.create_task(_body_pump())
        resp_task = asyncio.create_task(self._forward_response_head(ur, cw))

        _STREAM_ERRS: tuple[type[BaseException], ...] = (
            ProtocolError,
            ConnectionError,
            OSError,
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
        )

        async def _drain(t: asyncio.Task) -> None:
            if not t.done():
                t.cancel()
            try:
                await t
            except BaseException:  # noqa: BLE001 - errors already handled / irrelevant after cancel
                pass

        try:
            done, _pending = await asyncio.wait(
                [body_task, resp_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            await _drain(body_task)
            await _drain(resp_task)
            raise

        # The response watcher committing -- with or without error -- determines
        # this request's outcome. If it's still running, the body must have
        # completed; we wait for the response next.
        if resp_task not in done:
            # Only the body pump finished. If it errored we abandon the request;
            # otherwise we wait for the response head.
            if body_task.exception() is not None:
                await _drain(resp_task)
                await _fail(body_task.exception())
                return False
            try:
                await resp_task
            except _STREAM_ERRS as e:
                await _fail(e)
                return False
        else:
            # Response watcher completed first (or simultaneously). Stop the
            # body pump if it's still running -- upstream has already decided.
            if not body_task.done():
                await _drain(body_task)
                # Upstream's read buffer has a partial request; conn is unsafe
                # to reuse for another request.
                close_after_response = True
            elif body_task.exception() is not None:
                # Body finished and errored, but we have a response anyway.
                # Conn unsafe to reuse.
                close_after_response = True

        if resp_task.exception() is not None:
            await _fail(resp_task.exception())
            return False

        resp_start, resp_headers, status_code = resp_task.result()

        # ---------------- 101 Switching Protocols -> raw tunnel ----------------
        if status_code == 101:
            end = time.time()
            await self.storage.finalize(
                row_id,
                end_ts=end,
                duration_ms=(end - start_ts) * 1000.0,
                request_body_size=body_size_ref[0],
                status_code=status_code,
                response_headers=_decode_for_storage(resp_headers),
                response_body_path=None,
                response_body_size=0,
            )
            await _splice(cr, cw, ur, uw, timeout=self.idle_read_timeout)
            return False

        # ---------------- forward response body ----------------
        no_body = (
            method_str == "HEAD"
            or 100 <= status_code < 200
            or status_code in (204, 304)
        )
        if not no_body:
            resp_te = _find_header(resp_headers, b"Transfer-Encoding")
            resp_cl = _find_header(resp_headers, b"Content-Length")
            resp_chunked = _has_token(resp_te, b"chunked")
            try:
                async with aiofiles.open(resp_body_path, "wb") as tee:
                    if resp_chunked:
                        response_body_size = await _forward_chunked(
                            ur, cw, tee, timeout=self.idle_read_timeout
                        )
                    elif resp_cl is not None:
                        length = _parse_int(resp_cl)
                        if length < 0:
                            raise ProtocolError(f"Negative Content-Length: {length}")
                        if length > 0:
                            response_body_size = await _forward_content_length(
                                ur, cw, tee, length, timeout=self.idle_read_timeout
                            )
                    else:
                        # No framing headers: HTTP/1.0-style close-delimited body.
                        response_body_size = await _forward_until_close(
                            ur, cw, tee, timeout=self.idle_read_timeout
                        )
                        close_after_response = True
            except (
                ProtocolError,
                ConnectionError,
                OSError,
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,
            ) as e:
                await _fail(e)
                return False

        end = time.time()
        await self.storage.finalize(
            row_id,
            end_ts=end,
            duration_ms=(end - start_ts) * 1000.0,
            request_body_size=body_size_ref[0],
            status_code=status_code,
            response_headers=_decode_for_storage(resp_headers),
            response_body_path=resp_body_name if (not no_body) else None,
            response_body_size=response_body_size,
        )

        if close_after_response:
            return False
        if _wants_close(req_headers, http_version):
            return False
        if _wants_close(resp_headers, b"HTTP/1.1"):
            return False
        return True

    # ------------------------------------------------------------ helpers

    async def _forward_response_head(
        self,
        ur: asyncio.StreamReader,
        cw: asyncio.StreamWriter,
    ) -> tuple[bytes, list[tuple[bytes, bytes]], int]:
        """Read response heads, forwarding 1xx interim responses transparently,
        and return the final (non-1xx, or 101) response head."""
        while True:
            head_bytes = await _read_head(ur, timeout=self.idle_read_timeout)
            start, headers = _parse_header_block(head_bytes)
            _, status, _ = _parse_status_line(start)
            cw.write(_serialize_head(start, headers))
            await cw.drain()
            if 100 <= status < 200 and status != 101:
                continue
            return start, headers, status


# ============================================================ runner


async def run(
    *,
    host: str,
    port: int,
    upstream: str,
    verify_tls: bool,
    data_dir: Path,
    add_xff: bool = False,
    idle_read_timeout: float = IDLE_READ_TIMEOUT,
    upstream_connect_timeout: float = UPSTREAM_CONNECT_TIMEOUT,
) -> None:
    """Open storage, start the TCP server, serve forever."""
    storage = Storage(data_dir / "captures.db")
    await storage.open()
    try:
        proxy = TCPProxy(
            upstream=upstream,
            storage=storage,
            bodies_dir=data_dir / "bodies",
            verify_tls=verify_tls,
            add_xff=add_xff,
            idle_read_timeout=idle_read_timeout,
            upstream_connect_timeout=upstream_connect_timeout,
        )
        server = await asyncio.start_server(
            proxy.handle_connection,
            host=host,
            port=port,
            limit=STREAM_LIMIT,
        )
        try:
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            pass
    finally:
        await storage.close()
