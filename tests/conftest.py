"""Shared fixtures and helpers for tcp_proxy tests.

Everything in this file is deliberately *independent* of the production
parsing code in ``mitm_proxy.tcp_proxy`` -- we hand-roll a minimal HTTP/1.x
parser for the fake upstream so we're not validating the proxy against
itself.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional

import pytest_asyncio

from mitm_proxy.storage import Storage
from mitm_proxy.tcp_proxy import TCPProxy


# ============================================================ data types


@dataclass
class CapturedRequest:
    """One request seen by the fake upstream, with original bytes preserved."""

    start_line: bytes
    headers: list[tuple[bytes, bytes]]
    method: str
    target: str
    body: bytes
    raw_head: bytes
    raw_wire_body: bytes  # everything after the head CRLFCRLF, verbatim


Responder = Callable[[int, CapturedRequest], bytes]
RawHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter, "FakeUpstream"],
    Awaitable[None],
]


# ============================================================ tiny parser


def _parse_header_block(head: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    lines = head.split(b"\r\n")
    start = lines[0]
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (b" ", b"\t") and headers:
            n, v = headers[-1]
            headers[-1] = (n, v + b" " + line.lstrip())
            continue
        colon = line.find(b":")
        if colon > 0:
            name = line[:colon]
            value = line[colon + 1 :].lstrip(b" \t")
            headers.append((name, value))
    return start, headers


def _find(headers: list[tuple[bytes, bytes]], name: bytes) -> Optional[bytes]:
    nl = name.lower()
    for n, v in headers:
        if n.lower() == nl:
            return v
    return None


def _has_token(value: Optional[bytes], token: bytes) -> bool:
    if value is None:
        return False
    tl = token.lower()
    return any(p.strip().lower() == tl for p in value.split(b","))


async def _read_body(
    reader: asyncio.StreamReader, headers: list[tuple[bytes, bytes]]
) -> tuple[bytes, bytes]:
    """Read body using whatever framing the headers declare. Returns (decoded body, raw wire bytes consumed)."""
    te = _find(headers, b"Transfer-Encoding")
    cl = _find(headers, b"Content-Length")

    if _has_token(te, b"chunked"):
        decoded = bytearray()
        wire = bytearray()
        while True:
            size_line = await reader.readuntil(b"\r\n")
            wire += size_line
            n = int(size_line[:-2].split(b";")[0].strip(), 16)
            if n == 0:
                while True:
                    line = await reader.readuntil(b"\r\n")
                    wire += line
                    if line == b"\r\n":
                        break
                return bytes(decoded), bytes(wire)
            payload = await reader.readexactly(n)
            wire += payload
            decoded += payload
            crlf = await reader.readexactly(2)
            wire += crlf

    if cl is not None:
        length = int(cl)
        if length == 0:
            return b"", b""
        body = await reader.readexactly(length)
        return body, body

    return b"", b""


def _response_has_close(resp: bytes) -> bool:
    head_end = resp.find(b"\r\n\r\n")
    if head_end < 0:
        return False
    head = resp[:head_end]
    _, headers = _parse_header_block(head)
    return _has_token(_find(headers, b"Connection"), b"close")


# ============================================================ fake upstream


def _default_responder(_i: int, _req: CapturedRequest) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )


@dataclass
class FakeUpstream:
    host: str = "127.0.0.1"
    port: int = 0
    received: list[CapturedRequest] = field(default_factory=list)
    responder: Responder = _default_responder
    raw_handler: Optional[RawHandler] = None
    _server: Optional[asyncio.AbstractServer] = None

    @property
    def host_header(self) -> bytes:
        return f"{self.host}:{self.port}".encode("ascii")

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, host=self.host, port=0
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            if self.raw_handler is not None:
                await self.raw_handler(reader, writer, self)
                return
            await self._serve_loop(reader, writer)
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001 - close in finally must not throw
                pass

    async def _serve_loop(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            try:
                head_data = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=5.0
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return
            head_bytes = head_data[:-4]
            start_line, headers = _parse_header_block(head_bytes)
            try:
                body, wire_body = await asyncio.wait_for(
                    _read_body(reader, headers), timeout=5.0
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                return
            parts = start_line.split(b" ")
            method = parts[0].decode("ascii", "replace") if parts else ""
            target = parts[1].decode("latin-1", "replace") if len(parts) > 1 else ""
            req = CapturedRequest(
                start_line=start_line,
                headers=headers,
                method=method,
                target=target,
                body=body,
                raw_head=head_bytes,
                raw_wire_body=wire_body,
            )
            self.received.append(req)

            resp = self.responder(len(self.received) - 1, req)
            writer.write(resp)
            await writer.drain()

            if _has_token(_find(headers, b"Connection"), b"close"):
                return
            if _response_has_close(resp):
                return


# ============================================================ proxy handle


@dataclass
class ProxyHandle:
    host: str
    port: int
    data_dir: Path
    storage: Storage


# ============================================================ fixtures


@pytest_asyncio.fixture
async def fake_upstream():
    up = FakeUpstream()
    await up.start()
    try:
        yield up
    finally:
        await up.stop()


@pytest_asyncio.fixture
async def proxy(tmp_path: Path, fake_upstream: FakeUpstream):
    data_dir = tmp_path / "mitm"
    data_dir.mkdir()
    storage = Storage(data_dir / "captures.db")
    await storage.open()
    tcp_proxy = TCPProxy(
        upstream=f"http://{fake_upstream.host}:{fake_upstream.port}",
        storage=storage,
        bodies_dir=data_dir / "bodies",
        verify_tls=False,
    )
    server = await asyncio.start_server(
        tcp_proxy.handle_connection, host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield ProxyHandle(
            host="127.0.0.1", port=port, data_dir=data_dir, storage=storage
        )
    finally:
        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        await storage.close()


# ============================================================ helpers


async def raw_exchange(host: str, port: int, request_bytes: bytes) -> bytes:
    """Send raw request bytes and read response until EOF. Connection-close style tests."""
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(request_bytes)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=10.0)
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    return response


def fetch_rows(data_dir: Path) -> list[dict]:
    db_path = data_dir / "captures.db"
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute("SELECT * FROM requests ORDER BY id"))
    finally:
        conn.close()
    return [dict(r) for r in rows]


def fetch_headers_rows(data_dir: Path) -> list[dict]:
    db_path = data_dir / "captures.db"
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute("SELECT * FROM headers ORDER BY request_id, rowid"))
    finally:
        conn.close()
    return [dict(r) for r in rows]


def read_body_file(data_dir: Path, name: Optional[str]) -> bytes:
    assert name is not None, "expected a non-None body path"
    return (data_dir / "bodies" / name).read_bytes()


def decode_headers_json(s: Optional[str]) -> list[tuple[str, str]]:
    if not s:
        return []
    return [(n, v) for n, v in json.loads(s)]
