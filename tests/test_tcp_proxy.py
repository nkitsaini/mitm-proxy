"""Transparency + capture-correctness tests for the raw TCP proxy.

These tests verify two things at once on every exchange:

  1. **Byte transparency.** What the upstream receives equals what the client
     sent, modulo the single allowed mutation (``Host:`` value). What the
     client receives equals what the upstream sent, byte for byte.

  2. **Capture correctness.** The SQLite ``requests`` row and the on-disk body
     files contain accurate metadata + decoded bodies for the request.
"""

from __future__ import annotations

import asyncio

from .conftest import (
    FakeUpstream,
    ProxyHandle,
    decode_headers_json,
    fetch_headers_rows,
    fetch_rows,
    raw_exchange,
    read_body_file,
)


# ============================================================ basic GET


async def test_simple_get_with_content_length(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """A vanilla GET round-trips byte-perfectly and yields one finalized row."""
    scripted = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 5\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"hello"
    )
    fake_upstream.responder = lambda i, r: scripted

    request = (
        b"GET /foo?x=1 HTTP/1.1\r\n"
        b"Host: orig.example.com\r\n"
        b"User-Agent: test-agent/1.0\r\n"
        b"X-Custom-Header: Hello World\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    response = await raw_exchange(proxy.host, proxy.port, request)

    assert response == scripted

    assert len(fake_upstream.received) == 1
    req = fake_upstream.received[0]
    assert req.start_line == b"GET /foo?x=1 HTTP/1.1"
    assert req.method == "GET"
    assert req.target == "/foo?x=1"
    assert req.body == b""

    host_header = next(v for n, v in req.headers if n.lower() == b"host")
    assert host_header == fake_upstream.host_header
    ua = next(v for n, v in req.headers if n.lower() == b"user-agent")
    assert ua == b"test-agent/1.0"

    rows = fetch_rows(proxy.data_dir)
    assert len(rows) == 1
    row = rows[0]
    assert row["method"] == "GET"
    assert row["status_code"] == 200
    assert row["request_body_size"] == 0
    assert row["response_body_size"] == 5
    assert row["error"] is None
    assert row["duration_ms"] is not None and row["duration_ms"] >= 0
    assert row["client_ip"] == "127.0.0.1"


# ============================================================ no default header injection


async def test_no_default_headers_injected(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Upstream sees ONLY the headers the client sent (plus the rewritten Host)."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\n"
        b"Host: orig.example.com\r\n"
        b"X-Only: yes\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )

    req = fake_upstream.received[0]
    received_names_lower = sorted({n.lower() for n, _ in req.headers})
    # Exactly the three headers we expect upstream to see: Host, X-Only, Connection.
    assert received_names_lower == [b"connection", b"host", b"x-only"]
    # aiohttp would have injected user-agent + accept-encoding here.
    assert all(n.lower() != b"user-agent" for n, _ in req.headers)
    assert all(n.lower() != b"accept-encoding" for n, _ in req.headers)


# ============================================================ Host rewriting


async def test_host_header_rewritten_preserving_position_and_casing(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """The Host header's position in the header list and its name casing are kept; only the value changes."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\n"
        b"X-Before: 1\r\n"
        b"HoSt: orig.example.com\r\n"
        b"X-After: 2\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )

    req = fake_upstream.received[0]
    names_in_order = [n for n, _ in req.headers]
    assert names_in_order.index(b"X-Before") < names_in_order.index(b"HoSt")
    assert names_in_order.index(b"HoSt") < names_in_order.index(b"X-After")
    host_pair = next((n, v) for n, v in req.headers if n.lower() == b"host")
    assert host_pair[0] == b"HoSt"  # original casing preserved
    assert host_pair[1] == fake_upstream.host_header


async def test_host_header_inserted_when_absent(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """HTTP/1.0 clients may omit Host -- we synthesize one so upstream can route."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.0\r\nX-Foo: bar\r\nConnection: close\r\n\r\n",
    )

    req = fake_upstream.received[0]
    host = next((v for n, v in req.headers if n.lower() == b"host"), None)
    assert host == fake_upstream.host_header


# ============================================================ header order/case/dups


async def test_header_order_and_casing_preserved(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"X-zEbra: 1\r\n"
        b"x-alpha: 2\r\n"
        b"X-MIXED-Case: three\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )

    req = fake_upstream.received[0]
    # Original casing on each header name.
    name_set = {n for n, _ in req.headers}
    assert b"X-zEbra" in name_set
    assert b"x-alpha" in name_set
    assert b"X-MIXED-Case" in name_set
    # Original order.
    order = [n for n, _ in req.headers]
    assert order.index(b"X-zEbra") < order.index(b"x-alpha") < order.index(b"X-MIXED-Case")


async def test_duplicate_headers_preserved(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Multiple headers with the same name are passed through individually
    (e.g. ``Set-Cookie`` semantics on the response, ``X-Custom`` here)."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\n"
        b"Set-Cookie: a=1; Path=/\r\n"
        b"Set-Cookie: b=2; Path=/\r\n"
        b"Set-Cookie: c=3; HttpOnly\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"X-Dup: one\r\n"
        b"X-Dup: two\r\n"
        b"X-Dup: three\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )

    req = fake_upstream.received[0]
    dup_values = [v for n, v in req.headers if n.lower() == b"x-dup"]
    assert dup_values == [b"one", b"two", b"three"]

    # And the three Set-Cookie headers came back in order.
    head, _, _ = response.partition(b"\r\n\r\n")
    cookies = [line for line in head.split(b"\r\n") if line.lower().startswith(b"set-cookie:")]
    assert cookies == [
        b"Set-Cookie: a=1; Path=/",
        b"Set-Cookie: b=2; Path=/",
        b"Set-Cookie: c=3; HttpOnly",
    ]


# ============================================================ reason phrase / status line


async def test_reason_phrase_preserved(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Status line including the reason phrase is forwarded byte-for-byte."""
    scripted = (
        b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    assert response.startswith(b"HTTP/1.1 418 I'm a teapot\r\n")
    assert response == scripted

    rows = fetch_rows(proxy.data_dir)
    assert rows[0]["status_code"] == 418


async def test_custom_reason_phrase_preserved(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    scripted = (
        b"HTTP/1.1 200 LGTM friend!\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    assert response.split(b"\r\n", 1)[0] == b"HTTP/1.1 200 LGTM friend!"


# ============================================================ request body framings


async def test_post_content_length_request_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    )

    body = b'{"hello":"world"}'
    request = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )
    await raw_exchange(proxy.host, proxy.port, request)

    req = fake_upstream.received[0]
    assert req.method == "POST"
    assert req.body == body
    # Critically: Content-Length forwarded as-is (no chunked re-framing).
    cl = next(v for n, v in req.headers if n.lower() == b"content-length")
    assert cl == str(len(body)).encode()
    assert not any(n.lower() == b"transfer-encoding" for n, _ in req.headers)

    row = fetch_rows(proxy.data_dir)[0]
    assert row["request_body_size"] == len(body)
    assert read_body_file(proxy.data_dir, row["request_body_path"]) == body


async def test_post_chunked_request_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    chunked = (
        b"5\r\nhello\r\n"
        b"6\r\n world\r\n"
        b"0\r\n"
        b"\r\n"
    )
    request = (
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n" + chunked
    )
    await raw_exchange(proxy.host, proxy.port, request)

    req = fake_upstream.received[0]
    assert req.body == b"hello world"

    row = fetch_rows(proxy.data_dir)[0]
    assert row["request_body_size"] == len(b"hello world")
    # Body file contains decoded payload.
    assert read_body_file(proxy.data_dir, row["request_body_path"]) == b"hello world"


async def test_chunked_request_with_trailers_preserved(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Trailer headers after the terminating 0-chunk are forwarded byte-for-byte."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    chunked_with_trailers = (
        b"4\r\nWiki\r\n"
        b"5\r\npedia\r\n"
        b"0\r\n"
        b"X-Trailer-A: alpha\r\n"
        b"X-Trailer-B: bravo\r\n"
        b"\r\n"
    )
    request = (
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Trailer: X-Trailer-A, X-Trailer-B\r\n"
        b"Connection: close\r\n"
        b"\r\n" + chunked_with_trailers
    )
    await raw_exchange(proxy.host, proxy.port, request)

    req = fake_upstream.received[0]
    assert req.body == b"Wikipedia"
    # The trailer bytes are present verbatim in the wire bytes the upstream received.
    assert b"X-Trailer-A: alpha\r\n" in req.raw_wire_body
    assert b"X-Trailer-B: bravo\r\n" in req.raw_wire_body


# ============================================================ response body framings


async def test_chunked_response_body_decoded_to_capture_file(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    scripted = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"7\r\nMozilla\r\n"
        b"9\r\nDeveloper\r\n"
        b"7\r\nNetwork\r\n"
        b"0\r\n"
        b"\r\n"
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    # Client sees chunked framing verbatim.
    assert response == scripted

    row = fetch_rows(proxy.data_dir)[0]
    # File on disk holds the decoded payload, not the chunked frames.
    assert read_body_file(proxy.data_dir, row["response_body_path"]) == b"MozillaDeveloperNetwork"
    assert row["response_body_size"] == len(b"MozillaDeveloperNetwork")


async def test_content_length_response_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    payload = b"x" * 4096
    scripted = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + payload
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    assert response == scripted
    row = fetch_rows(proxy.data_dir)[0]
    assert row["response_body_size"] == len(payload)
    assert read_body_file(proxy.data_dir, row["response_body_path"]) == payload


async def test_close_delimited_response_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Response with no Content-Length and no Transfer-Encoding is read until EOF."""
    body = b"streamy" * 100
    scripted = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert response == scripted

    row = fetch_rows(proxy.data_dir)[0]
    assert row["response_body_size"] == len(body)
    assert read_body_file(proxy.data_dir, row["response_body_path"]) == body


# ============================================================ bodyless statuses / HEAD


async def test_204_no_content_has_no_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    scripted = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert response == scripted

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 204
    assert row["response_body_size"] == 0
    assert row["response_body_path"] is None


async def test_304_not_modified_has_no_body(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    scripted = (
        b"HTTP/1.1 304 Not Modified\r\n"
        b"ETag: \"abc\"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert response == scripted

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 304
    assert row["response_body_path"] is None


async def test_head_request_no_response_body_even_with_content_length(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """HEAD responses include framing headers but no body. The proxy must not try to read one."""
    scripted = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 1024\r\n"  # framing for the equivalent GET body
        b"Content-Type: application/octet-stream\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await asyncio.wait_for(
        raw_exchange(
            proxy.host,
            proxy.port,
            b"HEAD /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ),
        timeout=5.0,
    )
    assert response == scripted

    row = fetch_rows(proxy.data_dir)[0]
    assert row["method"] == "HEAD"
    assert row["status_code"] == 200
    assert row["response_body_path"] is None


# ============================================================ 1xx interim responses


async def test_103_early_hints_forwarded(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """An unsolicited 103 Early Hints must reach the client before the 200."""

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 103 Early Hints\r\n"
            b"Link: </main.css>; rel=preload; as=style\r\n"
            b"\r\n"
        )
        await writer.drain()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 11\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"hello world"
        )
        await writer.drain()

    fake_upstream.raw_handler = handler

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    assert response.startswith(b"HTTP/1.1 103 Early Hints\r\n")
    assert b"Link: </main.css>; rel=preload; as=style\r\n" in response
    assert b"\r\n\r\nHTTP/1.1 200 OK\r\n" in response
    assert response.endswith(b"hello world")

    rows = fetch_rows(proxy.data_dir)
    assert len(rows) == 1
    assert rows[0]["status_code"] == 200  # final response is what we capture


# ============================================================ 100-continue


async def test_100_continue_normal_flow(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Client says Expect: 100-continue, server says 100, client sends body, server says 200."""

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
        b"Expect: 100-continue\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()

    interim = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
    assert interim == b"HTTP/1.1 100 Continue\r\n\r\n"

    writer.write(b"hello world")
    await writer.drain()

    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 200 OK\r\n")
    assert final.endswith(b"OK")

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 200
    assert row["request_body_size"] == 11


async def test_100_continue_final_response_does_not_cancel_upload(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """After upstream sends 100, a queued final response must not stop body upload."""

    body_seen: list[bytes] = []

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        await writer.drain()
        writer.write(
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        await writer.drain()
        try:
            body_seen.append(await asyncio.wait_for(reader.readexactly(11), timeout=2.0))
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            body_seen.append(b"")

    fake_upstream.raw_handler = handler

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(
        b"POST /up HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Content-Length: 11\r\n"
        b"Expect: 100-continue\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()

    interim = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
    assert interim == b"HTTP/1.1 100 Continue\r\n\r\n"

    writer.write(b"hello world")
    await writer.drain()

    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 500 Internal Server Error\r\n")
    assert body_seen == [b"hello world"]

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass


async def test_100_continue_server_rejects(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Server answers 417 instead of 100; proxy must skip request-body forwarding."""

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 417 Expectation Failed\r\n"
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
        b"Content-Length: 11\r\n"
        b"Expect: 100-continue\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()

    final = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert final.startswith(b"HTTP/1.1 417 Expectation Failed\r\n")

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 417
    assert row["request_body_size"] == 0


# ============================================================ 101 Upgrade


async def test_101_upgrade_creates_raw_tunnel(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """After 101, the proxy must splice raw bytes bidirectionally."""

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"\r\n"
        )
        await writer.drain()
        # Echo any bytes the client sends after the upgrade, then close.
        while True:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            except asyncio.TimeoutError:
                return
            if not data:
                return
            writer.write(data)
            await writer.drain()
            if b"END" in data:
                # Drain a final write then EOF.
                try:
                    writer.write_eof()
                except (OSError, RuntimeError):
                    pass
                return

    fake_upstream.raw_handler = handler

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(
        b"GET /ws HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"\r\n"
    )
    await writer.drain()

    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
    assert head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n")
    assert b"Upgrade: websocket" in head

    writer.write(b"PING-END")
    await writer.drain()

    echoed = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert b"PING-END" in echoed

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass

    row = fetch_rows(proxy.data_dir)[0]
    assert row["status_code"] == 101
    # Bytes past the 101 are opaque and intentionally not captured to bodies.
    assert row["response_body_path"] is None


# ============================================================ keep-alive / multi-request


async def test_keepalive_multiple_requests_same_connection(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Three pipelined-but-sequential requests on one TCP conn produce three DB rows."""

    def responder(i, req):
        body = f"resp-{i}".encode()
        last = i == 2
        conn = b"close" if last else b"keep-alive"
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: " + conn + b"\r\n"
            b"\r\n" + body
        )

    fake_upstream.responder = responder

    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    for i in range(2):
        writer.write(
            b"GET /" + str(i).encode() + b" HTTP/1.1\r\n"
            b"Host: orig\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        await writer.drain()
        # Read head + body. Content-Length on each lets us frame.
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        cl = next(
            line for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")
        )
        n = int(cl.split(b":", 1)[1].strip())
        body = await reader.readexactly(n)
        assert body == f"resp-{i}".encode()

    # Third request asks for close so the conn tears down naturally.
    writer.write(
        b"GET /2 HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()
    rest = await asyncio.wait_for(reader.read(), timeout=5.0)
    assert rest.endswith(b"resp-2")

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass

    rows = fetch_rows(proxy.data_dir)
    assert len(rows) == 3
    assert [r["request_url"] for r in rows] == [
        "http://orig/0",
        "http://orig/1",
        "http://orig/2",
    ]
    # All three rows have unique trace_ids.
    assert len({r["trace_id"] for r in rows}) == 3
    assert [r["status_code"] for r in rows] == [200, 200, 200]
    assert [r["response_body_size"] for r in rows] == [6, 6, 6]
    assert len(fake_upstream.received) == 3


# ============================================================ HTTP/1.0 semantics


async def test_http_1_0_default_close(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """HTTP/1.0 without explicit keep-alive must close after one request."""

    scripted = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nHI"
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.0\r\nHost: orig\r\n\r\n",
    )
    # Note: aiohttp would have upgraded this to HTTP/1.1; we forward 1.0 verbatim.
    assert response == scripted


# ============================================================ DB shape


async def test_request_url_and_upstream_url_in_db(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET /a/b/c?q=1&r=2 HTTP/1.1\r\nHost: orig.example.com\r\nConnection: close\r\n\r\n",
    )

    row = fetch_rows(proxy.data_dir)[0]
    assert row["request_url"] == "http://orig.example.com/a/b/c?q=1&r=2"
    assert row["upstream_url"] == (
        f"http://{fake_upstream.host}:{fake_upstream.port}/a/b/c?q=1&r=2"
    )


async def test_headers_persisted_in_both_json_and_exploded_tables(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\n"
        b"X-Trace-Id: abc-123\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\n"
        b"Host: orig\r\n"
        b"X-Marker: hello\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )

    rows = fetch_rows(proxy.data_dir)
    assert len(rows) == 1
    row = rows[0]

    req_hdrs = decode_headers_json(row["request_headers_json"])
    req_names = [n.lower() for n, _ in req_hdrs]
    assert "host" in req_names
    assert "x-marker" in req_names
    host_val = next(v for n, v in req_hdrs if n.lower() == "host")
    assert host_val == f"{fake_upstream.host}:{fake_upstream.port}"

    resp_hdrs = decode_headers_json(row["response_headers_json"])
    resp_names = [n.lower() for n, _ in resp_hdrs]
    assert "x-trace-id" in resp_names
    assert next(v for n, v in resp_hdrs if n.lower() == "x-trace-id") == "abc-123"

    h_rows = fetch_headers_rows(proxy.data_dir)
    by_dir = {"req": [], "resp": []}
    for hr in h_rows:
        by_dir[hr["direction"]].append((hr["name_lower"], hr["value"]))
    assert ("x-marker", "hello") in by_dir["req"]
    assert ("x-trace-id", "abc-123") in by_dir["resp"]


async def test_duration_ms_recorded(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    row = fetch_rows(proxy.data_dir)[0]
    assert row["duration_ms"] is not None
    assert 0.0 <= row["duration_ms"] < 5_000.0
    assert row["end_ts"] is not None and row["end_ts"] >= row["start_ts"]
    assert row["trace_id"] is not None and len(row["trace_id"]) > 0


async def test_no_request_body_means_no_request_body_file(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """A bodyless GET must not produce a ``<trace>.req`` file on disk."""
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    row = fetch_rows(proxy.data_dir)[0]
    assert row["request_body_path"] is None
    bodies = proxy.data_dir / "bodies"
    # No `.req` file should have been written for this request.
    assert all(not p.name.endswith(".req") for p in bodies.iterdir())


# ============================================================ streaming / memory


async def test_large_body_streams_without_buffering(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """A multi-MB response round-trips and ends up correctly on disk.

    The proxy's CHUNK_SIZE is 64 KiB and bodies are never buffered fully; if
    we mistakenly tried to, this 4 MiB payload would still pass but resource
    behavior would degrade. Correctness is what we assert here.
    """
    payload = (b"abcdefghij" * 102_400)  # 1,024,000 bytes
    payload = payload * 4  # ~4 MiB
    scripted = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + payload
    )
    fake_upstream.responder = lambda i, r: scripted

    response = await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    assert len(response) == len(scripted)
    assert response == scripted

    row = fetch_rows(proxy.data_dir)[0]
    assert row["response_body_size"] == len(payload)
    assert read_body_file(proxy.data_dir, row["response_body_path"]) == payload


# ============================================================ failure recording


async def test_upstream_sends_garbage_records_error(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    """Malformed upstream response should be recorded as an error on the row."""

    async def handler(reader, writer, up):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"this is not http\r\n\r\n")
        await writer.drain()

    fake_upstream.raw_handler = handler

    # Best-effort: we don't really care what the client sees (proxy will close
    # without writing a response), but we do care about the DB row.
    try:
        await asyncio.wait_for(
            raw_exchange(
                proxy.host,
                proxy.port,
                b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            ),
            timeout=5.0,
        )
    except asyncio.TimeoutError:
        pass

    rows = fetch_rows(proxy.data_dir)
    assert len(rows) == 1
    assert rows[0]["status_code"] is None
    assert rows[0]["error"] is not None
    assert "ProtocolError" in rows[0]["error"]


# ============================================================ trace_id format


async def test_trace_id_is_hex32(
    proxy: ProxyHandle, fake_upstream: FakeUpstream
) -> None:
    fake_upstream.responder = lambda i, r: (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )

    await raw_exchange(
        proxy.host,
        proxy.port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )

    row = fetch_rows(proxy.data_dir)[0]
    assert len(row["trace_id"]) == 32
    int(row["trace_id"], 16)  # raises if not hex
