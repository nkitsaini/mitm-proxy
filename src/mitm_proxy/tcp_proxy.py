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
import ssl as ssl_lib
import time
import uuid
from pathlib import Path
from typing import Any, Optional
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


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    """Read up to (but not including) the CRLFCRLF terminator of an HTTP message head."""
    try:
        data = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=IDLE_READ_TIMEOUT
        )
    except asyncio.LimitOverrunError as e:
        raise ProtocolError(f"Header block exceeds {STREAM_LIMIT} bytes") from e
    return data[:-4]


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    try:
        return await asyncio.wait_for(
            reader.readuntil(b"\r\n"), timeout=IDLE_READ_TIMEOUT
        )
    except asyncio.LimitOverrunError as e:
        raise ProtocolError(f"Line exceeds {STREAM_LIMIT} bytes") from e


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await asyncio.wait_for(reader.readexactly(n), timeout=IDLE_READ_TIMEOUT)


async def _read_some(reader: asyncio.StreamReader, n: int) -> bytes:
    return await asyncio.wait_for(reader.read(n), timeout=IDLE_READ_TIMEOUT)


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


# =========================================================== body forwarding


# aiofiles' file-like object; we only call .write() on it.
BodyTee = Optional[Any]


async def _forward_content_length(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tee: BodyTee,
    length: int,
) -> int:
    remaining = length
    while remaining > 0:
        chunk = await _read_some(reader, min(CHUNK_SIZE, remaining))
        if not chunk:
            raise ProtocolError("EOF before Content-Length body fully read")
        writer.write(chunk)
        if tee is not None:
            await tee.write(chunk)
        remaining -= len(chunk)
        await writer.drain()
    return length


async def _forward_chunked(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tee: BodyTee,
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
        size_line = await _read_line(reader)
        writer.write(size_line)
        size_hex = size_line[:-2].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_hex, 16)
        except ValueError as e:
            raise ProtocolError(f"Bad chunk size: {size_line!r}") from e
        if chunk_size < 0:
            raise ProtocolError(f"Negative chunk size: {chunk_size}")
        if chunk_size == 0:
            # Optional trailer header block, terminated by a bare CRLF.
            while True:
                line = await _read_line(reader)
                writer.write(line)
                if line == b"\r\n":
                    break
            await writer.drain()
            return decoded
        remaining = chunk_size
        while remaining > 0:
            chunk = await _read_some(reader, min(CHUNK_SIZE, remaining))
            if not chunk:
                raise ProtocolError("EOF mid chunk payload")
            writer.write(chunk)
            if tee is not None:
                await tee.write(chunk)
            decoded += len(chunk)
            remaining -= len(chunk)
        crlf = await _read_exact(reader, 2)
        if crlf != b"\r\n":
            raise ProtocolError("Missing CRLF after chunk")
        writer.write(crlf)
        await writer.drain()


async def _forward_until_close(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tee: BodyTee,
) -> int:
    """Read from reader until EOF, forward all bytes. Used for close-delimited
    responses (no Content-Length, no Transfer-Encoding). Forces connection close
    after, since the message boundary is the connection boundary."""
    total = 0
    while True:
        chunk = await _read_some(reader, CHUNK_SIZE)
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
) -> None:
    """Bidirectional raw byte forwarding between two endpoints.

    Used after a 101 Switching Protocols response when the connection becomes
    an opaque sub-protocol tunnel (WebSockets, h2c, etc.). Captures nothing
    once we're past 101 -- the bytes aren't HTTP anymore.
    """

    async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await _read_some(src, CHUNK_SIZE)
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
        if parsed.scheme == "https":
            self.ssl_ctx: Optional[ssl_lib.SSLContext] = ssl_lib.create_default_context()
            if not verify_tls:
                self.ssl_ctx.check_hostname = False
                self.ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        else:
            self.ssl_ctx = None

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
                    timeout=UPSTREAM_CONNECT_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError, ssl_lib.SSLError):
                return
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
            req_head_bytes = await _read_head(cr)
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
        expect_continue = _has_token(
            _find_header(req_headers, b"Expect"), b"100-continue"
        )

        # The single mutation: rewrite the Host header value for upstream.
        rewritten_headers = _rewrite_host(req_headers, self.upstream_host_header)

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

        request_body_size = 0
        response_body_size = 0

        async def _fail(exc: BaseException) -> None:
            end = time.time()
            await self.storage.fail(
                row_id,
                end_ts=end,
                duration_ms=(end - start_ts) * 1000.0,
                request_body_size=request_body_size,
                error=f"{type(exc).__name__}: {exc}",
            )

        # ---------------- forward request head ----------------
        try:
            uw.write(_serialize_head(req_start, rewritten_headers))
            await uw.drain()
        except (ConnectionError, OSError) as e:
            await _fail(e)
            return False

        # ---------------- Expect: 100-continue dance ----------------
        # If the client is waiting for an interim response before sending its
        # body, drain upstream first so we don't deadlock. If upstream answers
        # with anything other than 100, that becomes the final response and we
        # skip body forwarding.
        early_final: Optional[tuple[bytes, list[tuple[bytes, bytes]], int]] = None
        if expect_continue:
            try:
                early_final = await self._forward_until_continue_or_final(ur, cw)
            except (
                ProtocolError,
                ConnectionError,
                OSError,
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,
            ) as e:
                await _fail(e)
                return False

        if early_final is None:
            # ---------------- forward request body ----------------
            if req_has_body:
                try:
                    async with aiofiles.open(req_body_path, "wb") as tee:
                        if req_chunked:
                            request_body_size = await _forward_chunked(cr, uw, tee)
                        else:
                            length = _parse_int(req_cl)
                            if length < 0:
                                raise ProtocolError(
                                    f"Negative Content-Length: {length}"
                                )
                            request_body_size = await _forward_content_length(
                                cr, uw, tee, length
                            )
                except (
                    ProtocolError,
                    ConnectionError,
                    OSError,
                    asyncio.TimeoutError,
                    asyncio.IncompleteReadError,
                ) as e:
                    await _fail(e)
                    return False

            # ---------------- read & forward response head(s) ----------------
            try:
                resp_start, resp_headers, status_code = await self._forward_response_head(
                    ur, cw
                )
            except (
                ProtocolError,
                ConnectionError,
                OSError,
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,
            ) as e:
                await _fail(e)
                return False
        else:
            resp_start, resp_headers, status_code = early_final

        # ---------------- 101 Switching Protocols -> raw tunnel ----------------
        if status_code == 101:
            end = time.time()
            await self.storage.finalize(
                row_id,
                end_ts=end,
                duration_ms=(end - start_ts) * 1000.0,
                request_body_size=request_body_size,
                status_code=status_code,
                response_headers=_decode_for_storage(resp_headers),
                response_body_path=None,
                response_body_size=0,
            )
            await _splice(cr, cw, ur, uw)
            return False

        # ---------------- forward response body ----------------
        no_body = (
            method_str == "HEAD"
            or 100 <= status_code < 200
            or status_code in (204, 304)
        )
        close_after_response = False
        if not no_body:
            resp_te = _find_header(resp_headers, b"Transfer-Encoding")
            resp_cl = _find_header(resp_headers, b"Content-Length")
            resp_chunked = _has_token(resp_te, b"chunked")
            try:
                async with aiofiles.open(resp_body_path, "wb") as tee:
                    if resp_chunked:
                        response_body_size = await _forward_chunked(ur, cw, tee)
                    elif resp_cl is not None:
                        length = _parse_int(resp_cl)
                        if length < 0:
                            raise ProtocolError(f"Negative Content-Length: {length}")
                        if length > 0:
                            response_body_size = await _forward_content_length(
                                ur, cw, tee, length
                            )
                    else:
                        # No framing headers: HTTP/1.0-style close-delimited body.
                        response_body_size = await _forward_until_close(ur, cw, tee)
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
            request_body_size=request_body_size,
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

    async def _forward_until_continue_or_final(
        self,
        ur: asyncio.StreamReader,
        cw: asyncio.StreamWriter,
    ) -> Optional[tuple[bytes, list[tuple[bytes, bytes]], int]]:
        """Drain interim responses from upstream until we see either a 100
        Continue (return None; the caller proceeds to forward the request body)
        or a final response that pre-empts the body (return it).
        """
        while True:
            head_bytes = await _read_head(ur)
            start, headers = _parse_header_block(head_bytes)
            _, status, _ = _parse_status_line(start)
            cw.write(_serialize_head(start, headers))
            await cw.drain()
            if status == 100:
                return None
            if 100 <= status < 200 and status != 101:
                continue
            return (start, headers, status)

    async def _forward_response_head(
        self,
        ur: asyncio.StreamReader,
        cw: asyncio.StreamWriter,
    ) -> tuple[bytes, list[tuple[bytes, bytes]], int]:
        """Read response heads, forwarding 1xx interim responses transparently,
        and return the final (non-1xx, or 101) response head."""
        while True:
            head_bytes = await _read_head(ur)
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
