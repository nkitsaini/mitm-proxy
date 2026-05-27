# mitm-proxy

A small streaming HTTP forwarding proxy that captures every request and
response (status, headers, full body) to disk and indexes the metadata in
SQLite so you can query the traffic later with `mitm-proxy list / show / body`
or plain `sqlite3`.

## What's inside

- **`src/mitm_proxy/proxy.py`** &mdash; aiohttp reverse proxy. Bodies are
  *streamed* end-to-end with a "tee" async generator that writes each chunk
  to disk as it forwards it to the other side. Memory use is bounded by
  `CHUNK_SIZE` (64 KiB), independent of body size.
- **`src/mitm_proxy/storage.py`** &mdash; aiosqlite schema. One row per request,
  plus a flattened `headers` table for easy header lookups.
- **`src/mitm_proxy/cli.py`** &mdash; `mitm-proxy serve / list / show / body /
  stats` commands.

## Install

```bash
uv sync
```

That's it. `uv` resolves and installs everything into `.venv`.

## Run the proxy

```bash
uv run mitm-proxy serve \
    --host 127.0.0.1 --port 8080 \
    --upstream {upstreamURL} \
    --data-dir ./mitm-data
```

Point your client at `http://127.0.0.1:8080/...` instead of the production
URL. Everything &mdash; status code, headers (request and response), and full
bodies &mdash; is captured to `./mitm-data/`.

Flags:

| flag                   | default        | meaning                                                              |
| ---------------------- | -------------- | -------------------------------------------------------------------- |
| `--host`               | `127.0.0.1`    | Bind address.                                                        |
| `--port`               | `8080`         | Bind port.                                                           |
| `--upstream`           | *(required)*   | Base URL of the real server. Path + query are forwarded verbatim.    |
| `--data-dir`           | `./mitm-data`  | Holds `captures.db` and `bodies/`.                                   |
| `--insecure-upstream`  | off            | Skip TLS verification when calling upstream (dev only).              |

### Layout of the data dir

```
mitm-data/
  captures.db          # SQLite (WAL mode)
  bodies/
    <trace_id>.req     # raw request body, exactly as the client sent it
    <trace_id>.resp    # raw response body (NOT auto-decompressed)
```

Bodies are stored **as they came off the wire**: if upstream sent
`Content-Encoding: gzip`, the `.resp` file is gzipped. The original
`Content-Encoding` header is preserved end-to-end, so your real client still
decompresses correctly. To inspect on disk:

```bash
mitm-proxy body 42 --direction resp | gunzip | jq .
```

## Query the captures

### Built-in CLI

```bash
# 20 most recent captures
uv run mitm-proxy list

# Only /pythonudfs traffic
uv run mitm-proxy list --path-like '%/pythonudfs/%'

# Errors only
uv run mitm-proxy list --errors-only

# All POSTs to a particular path that returned 401
uv run mitm-proxy list --method POST --status 401 --path-like '%/auth%'

# Full headers + body file paths for one request
uv run mitm-proxy show 42
uv run mitm-proxy show <trace_id>

# Cat the body to stdout (binary-safe)
uv run mitm-proxy body 42 --direction req
uv run mitm-proxy body 42 --direction resp | hexdump -C | head

# Aggregates
uv run mitm-proxy stats
```

### Direct SQL

The DB has two tables and one helper view:

```sql
-- one row per captured request
SELECT * FROM v_requests ORDER BY id DESC LIMIT 10;

-- find every request that sent a specific cluster ID
SELECT r.id, r.method, r.request_url, r.status_code
FROM requests r
JOIN headers h ON h.request_id = r.id
WHERE h.direction = 'req'
  AND h.name_lower = 's2-db-clusterid'
  AND h.value = '<UUID>';

-- p95 latency by status code
SELECT status_code,
       COUNT(*) AS n,
       AVG(duration_ms) AS avg_ms,
       MAX(duration_ms) AS max_ms
FROM requests
WHERE status_code IS NOT NULL
GROUP BY status_code;
```

Open directly with: `sqlite3 mitm-data/captures.db`.

## Streaming guarantees

* The request body is read with `request.content.iter_chunked(64 KiB)` and
  forwarded to upstream via an `AsyncIterator[bytes]`. aiohttp uses chunked
  transfer encoding on the outbound leg, so the full body is **never held in
  memory** &mdash; the highest watermark is one 64 KiB chunk while it is being
  written to disk and pushed onto the upstream socket.
* The response body is read with `upstream_resp.content.iter_chunked(64 KiB)`
  and pushed into `web.StreamResponse.write()` chunk-by-chunk, again with
  chunked encoding back to the client.
* `auto_decompress=False` on the upstream client ensures we tee the raw,
  compressed bytes to disk rather than allocating a decompressed copy.
* TCP backpressure naturally throttles the pipeline: if disk writes or the
  downstream socket fall behind, the upstream read loop awaits.

## Notes & limitations

* **HTTP only on the listening side.** Local proxy is plain HTTP. The
  upstream side speaks whatever the URL specifies (use `https://...` for TLS
  to production). If you need real `https://our-proxy.com` ingress, terminate
  TLS in front (Caddy, nginx, `mkcert`-signed cert + a tiny TLS wrapper, etc.)
  and point it at this proxy.
* **No request rewriting** &mdash; this is a pure forwarder. Add it in
  `Proxy.handle` if you need to mutate headers/paths.
* **Headers are stripped per RFC 7230 §6.1** (hop-by-hop) plus `Host` and
  `Content-Length` because we re-frame everything as chunked.
* **mTLS / client certs** are not handled. If your upstream requires a
  client certificate, configure it on the `aiohttp.TCPConnector` in
  `Proxy.on_startup`.

## Layout

```
mitm_proxy/
├── pyproject.toml
├── README.md
├── .python-version
├── .gitignore
└── src/mitm_proxy/
    ├── __init__.py
    ├── cli.py
    ├── proxy.py
    └── storage.py
```
