"""Tests for concurrent body-upload + response-head reading (option G).

A direct (no-proxy) connection lets upstream emit a 1xx interim response
(``100 Continue``, ``103 Early Hints``) at *any* time -- including while the
client is still uploading the request body, or *before* it has sent any body
at all (even without ``Expect: 100-continue``). The proxy must forward those
1xx responses promptly; a naive sequential pump that reads the response head
only after finishing body upload would either delay them or deadlock outright
when the client is waiting on the 1xx before sending the body.

These tests exercise scenarios where a sequential implementation would either
hang for the full idle-read timeout or reorder the 1xx behind the final
response.
"""

from __future__ import annotations

import asyncio

from .conftest import (
    FakeUpstream,
    ProxyHandle,
    fetch_rows,
)


# ============================================================ helpers


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass


# ============================================================ unsolicited 100


async def test_unsolicited_100_continue_without_expect_forwarded_before_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Upstream may send 100 Continue even without the client asking for it
    via ``Expect``. The proxy must forward it immediately so the client can
    proceed to send its body.

    Sequential pump: the proxy reads the body from the client before reading
    upstream, but the client is waiting for the 100 -> deadlock until
    idle-read timeout. With concurrent body-upload + response-watcher this
    just works.
    """

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()
        body = await reader.readexactly(11)
        assert body == b"hello world"
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"OK"
        )
        await writer.drain()

    fake_upstream.raw_handler = handler

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Content-Length: 11\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()

    # If the proxy buffers the 100 until after body upload, this readuntil
    # will time out because the test client deliberately doesn't send the
    # body yet.
    interim = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
    assert interim == b"HTTP/1.1 100 Continue\r\n\r\n"

    writer.write(b"hello world")
    await writer.drain()

    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 200 OK\r\n")
    assert final.endswith(b"OK")

    await _close(writer)

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 200
    assert row["request_body_size"] == 11


# ============================================================ 1xx during body


async def test_103_early_hints_arrives_while_body_uploading(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Upstream emits 103 Early Hints between the first and second halves of
    a chunked request body. The client must see the 103 before sending the
    second chunk -- which it explicitly waits for.

    This is the canonical "Early Hints during upload" scenario. A sequential
    proxy would only deliver the 103 after the whole request body finished
    uploading.
    """

    second_chunk_ready = asyncio.Event()

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        # Read first chunk: "5\r\nfirst\r\n"
        line = await reader.readuntil(b"\r\n")
        assert line == b"5\r\n"
        assert await reader.readexactly(5) == b"first"
        assert await reader.readexactly(2) == b"\r\n"

        # Send 103 right after first chunk, before reading the rest.
        writer.write(
            b"HTTP/1.1 103 Early Hints\r\n"
            b"Link: </a.css>; rel=preload\r\n"
            b"\r\n"
        )
        await writer.drain()

        # Read second chunk + terminator.
        line = await reader.readuntil(b"\r\n")
        assert line == b"6\r\n"
        assert await reader.readexactly(6) == b"second"
        assert await reader.readexactly(2) == b"\r\n"
        assert await reader.readuntil(b"\r\n\r\n") == b"0\r\n\r\n"

        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"OK"
        )
        await writer.drain()

    fake_upstream.raw_handler = handler

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"5\r\nfirst\r\n"
    )
    await writer.drain()

    # Spawn a watcher that waits for the 103 to arrive before the test sends
    # the second chunk. If the proxy is sequential this readuntil will time
    # out because the proxy is still trying to drain the request body.
    async def wait_for_hints() -> bytes:
        return await reader.readuntil(b"\r\n\r\n")

    hints_task = asyncio.create_task(wait_for_hints())
    interim = await asyncio.wait_for(hints_task, timeout=5.0)
    assert interim.startswith(b"HTTP/1.1 103 Early Hints\r\n")
    assert b"Link: </a.css>; rel=preload\r\n" in interim

    second_chunk_ready.set()
    writer.write(b"6\r\nsecond\r\n0\r\n\r\n")
    await writer.drain()

    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 200 OK\r\n")
    assert final.endswith(b"OK")

    await _close(writer)

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 200
    # Decoded body size = 5 + 6.
    assert row["request_body_size"] == 11


# ============================================================ early final response


async def test_final_response_before_body_upload_cancels_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Upstream rejects the request based on headers alone (no ``Expect``
    sent) and emits a final 4xx before reading the body. The proxy must
    forward the final response and not block waiting for the body.

    Note: while this exercises the same path that ``Expect: 100-continue``
    rejects use (in ``test_100_continue_server_rejects``), here the *client*
    never sent ``Expect`` -- meaning the proxy can't rely on that header to
    decide to drain upstream first. The concurrent design handles both cases
    identically.
    """

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        # Don't read any body. Reject immediately.
        writer.write(
            b"HTTP/1.1 413 Payload Too Large\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        await writer.drain()

    fake_upstream.raw_handler = handler

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Content-Length: 1000000\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()

    # Client hasn't sent any body yet. A sequential proxy would block
    # reading the (unsent) body before reading upstream -> deadlock.
    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 413 Payload Too Large\r\n")

    await _close(writer)

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 413
    assert row["request_body_size"] == 0


# ============================================================ partial body then early final


async def test_final_response_mid_body_cancels_remaining_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Client is uploading a large body; upstream decides to reject after
    seeing part of it, before reading the rest. The proxy forwards the final
    response and stops pumping the (potentially endless) remaining body
    instead of blocking waiting for it.
    """

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        # Consume just 5 bytes of the body, then reject.
        _ = await reader.readexactly(5)
        writer.write(
            b"HTTP/1.1 422 Unprocessable Entity\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        await writer.drain()

    fake_upstream.raw_handler = handler

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Content-Length: 10000\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    # Send the first slice of the declared body and then stop. The proxy
    # should still surface the rejection and tear the connection down
    # rather than waiting for the rest of the (declared) 10000 bytes.
    writer.write(b"first" + b"x" * 100)
    await writer.drain()

    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 422 Unprocessable Entity\r\n")

    await _close(writer)

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 422
