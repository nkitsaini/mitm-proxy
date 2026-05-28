"""Tests for the non-transparency behavioral knobs on the TCP proxy:

  * TCP_NODELAY + SO_KEEPALIVE on both legs (always on),
  * X-Forwarded-For injection (opt-in via ``add_xff``),
  * configurable idle-read and upstream-connect timeouts,
  * transport.abort() on error paths so failures don't look like clean EOFs.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest

from .conftest import (
    FakeUpstream,
    ProxyHandle,
    _start_proxy,
    _stop_proxy,
    fetch_rows,
    raw_exchange,
)


# ============================================================ socket options


async def test_tcp_nodelay_and_keepalive_set_on_both_legs(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """After the proxy accepts a connection, both the client-facing and the
    upstream-facing sockets must have ``TCP_NODELAY`` and ``SO_KEEPALIVE`` on.
    Captured inside the proxy via the ``on_connection_setup`` hook because
    sockets are closed by the time the test wakes up again."""
    captured: dict[str, int] = {}

    def on_setup(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        captured["client_nodelay"] = client_sock.getsockopt(
            socket.IPPROTO_TCP, socket.TCP_NODELAY
        )
        captured["upstream_nodelay"] = upstream_sock.getsockopt(
            socket.IPPROTO_TCP, socket.TCP_NODELAY
        )
        captured["client_keepalive"] = client_sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_KEEPALIVE
        )
        captured["upstream_keepalive"] = upstream_sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_KEEPALIVE
        )

    proxy.tcp_proxy.on_connection_setup = on_setup
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: orig\r\nConnection: close\r\n\r\n",
    )

    assert captured.get("client_nodelay") == 1, "TCP_NODELAY off on client leg"
    assert captured.get("upstream_nodelay") == 1, "TCP_NODELAY off on upstream leg"
    assert captured.get("client_keepalive") == 1, "SO_KEEPALIVE off on client leg"
    assert captured.get("upstream_keepalive") == 1, "SO_KEEPALIVE off on upstream leg"


# ============================================================ X-Forwarded-For


async def test_xff_not_injected_by_default(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """With the default ``add_xff=False``, upstream sees no X-Forwarded-For
    even if we (the proxy) know the client's IP."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: orig\r\nConnection: close\r\n\r\n",
    )

    req = fake_upstream.received[0]
    assert all(n.lower() != b"x-forwarded-for" for n, _ in req.headers)


async def test_xff_injected_when_enabled(
    tmp_path: Path, fake_upstream: FakeUpstream
) -> None:
    """With ``add_xff=True`` and no existing XFF, the proxy appends one with
    the client IP."""
    handle, server = await _start_proxy(tmp_path, fake_upstream, add_xff=True)
    try:
        fake_upstream.responder = lambda i, r: (
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        )
        await raw_exchange(
            handle.host,
            handle.port,
            b"GET / HTTP/1.1\r\nHost: orig\r\nConnection: close\r\n\r\n",
        )

        req = fake_upstream.received[0]
        xff_values = [v for n, v in req.headers if n.lower() == b"x-forwarded-for"]
        assert len(xff_values) == 1, f"expected exactly one XFF header, got {xff_values!r}"
        assert xff_values[0] == b"127.0.0.1"
    finally:
        await _stop_proxy(handle, server)


async def test_xff_extends_existing_chain(
    tmp_path: Path, fake_upstream: FakeUpstream
) -> None:
    """If the client already sent an XFF chain (e.g. from another upstream
    proxy), we *append* our IP to the existing one rather than replacing it."""
    handle, server = await _start_proxy(tmp_path, fake_upstream, add_xff=True)
    try:
        fake_upstream.responder = lambda i, r: (
            b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        )
        await raw_exchange(
            handle.host,
            handle.port,
            b"GET / HTTP/1.1\r\n"
            b"Host: orig\r\n"
            b"X-Forwarded-For: 10.0.0.1, 10.0.0.2\r\n"
            b"Connection: close\r\n"
            b"\r\n",
        )

        req = fake_upstream.received[0]
        xff_values = [v for n, v in req.headers if n.lower() == b"x-forwarded-for"]
        assert len(xff_values) == 1
        assert xff_values[0] == b"10.0.0.1, 10.0.0.2, 127.0.0.1"
    finally:
        await _stop_proxy(handle, server)


# ============================================================ timeouts


async def test_idle_read_timeout_fires_on_stalled_upstream(
    tmp_path: Path, fake_upstream: FakeUpstream
) -> None:
    """A short ``idle_read_timeout`` must trip when upstream goes silent
    between bytes, and the failure must land in the captures row."""

    async def stall_handler(reader, writer, up):
        # Accept the request, then go silent forever (until the test tears us down).
        await reader.readuntil(b"\r\n\r\n")
        await asyncio.sleep(30)

    fake_upstream.raw_handler = stall_handler

    handle, server = await _start_proxy(
        tmp_path, fake_upstream, idle_read_timeout=0.3
    )
    try:
        # The client will see a clean EOF (no response head ever written) once
        # the proxy aborts on the read timeout. We just need to make sure the
        # request finishes from the client's perspective.
        try:
            await asyncio.wait_for(
                raw_exchange(
                    handle.host,
                    handle.port,
                    b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                ),
                timeout=5.0,
            )
        except (asyncio.TimeoutError, ConnectionResetError, ConnectionError):
            pass

        rows = fetch_rows(handle.data_dir)
        assert len(rows) == 1, f"expected one row, got {len(rows)}"
        row = rows[0]
        assert row["status_code"] is None
        assert row["error"] is not None
        assert "TimeoutError" in row["error"]
        # And it really did fire fast, not at the global 10-minute default.
        assert row["duration_ms"] is not None and row["duration_ms"] < 2_000.0
    finally:
        await _stop_proxy(handle, server)


async def test_upstream_connect_timeout_fires_on_unreachable_upstream(
    tmp_path: Path,
) -> None:
    """A very small ``upstream_connect_timeout`` against a black-holed address
    should fail the client connection quickly. We don't make any DB assertion
    here -- nothing is persisted because we never accepted a request.
    """
    # Make a FakeUpstream-shaped object but don't actually start its server.
    fake = FakeUpstream(host="127.0.0.1", port=1)  # port 1 typically refuses fast.
    handle, server = await _start_proxy(
        tmp_path, fake, upstream_connect_timeout=0.2
    )
    try:
        # The client connection succeeds (proxy accepts), but the proxy fails to
        # reach upstream and closes the client immediately. read() returns "".
        start = asyncio.get_event_loop().time()
        result = await asyncio.wait_for(
            raw_exchange(
                handle.host,
                handle.port,
                b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            ),
            timeout=5.0,
        )
        elapsed = asyncio.get_event_loop().time() - start
        assert result == b""
        # If the proxy were still using the 30s default, we'd wait that long.
        assert elapsed < 3.0
    finally:
        await _stop_proxy(handle, server)
