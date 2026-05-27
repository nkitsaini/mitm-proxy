"""SQLite-backed storage for proxy capture metadata.

Bodies are written to the filesystem as the proxy streams them; this module
only persists references (file paths) plus headers/status/timing in a single
SQLite database. The schema is intentionally flat so it can be queried with
plain `sqlite3` from the shell.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Iterable

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_id              TEXT    NOT NULL UNIQUE,
  start_ts              REAL    NOT NULL,
  end_ts                REAL,
  duration_ms           REAL,
  client_ip             TEXT,
  method                TEXT    NOT NULL,
  request_url           TEXT    NOT NULL,
  upstream_url          TEXT    NOT NULL,
  request_headers_json  TEXT    NOT NULL,
  request_body_path     TEXT,
  request_body_size     INTEGER NOT NULL DEFAULT 0,
  status_code           INTEGER,
  response_headers_json TEXT,
  response_body_path    TEXT,
  response_body_size    INTEGER NOT NULL DEFAULT 0,
  error                 TEXT
);

CREATE INDEX IF NOT EXISTS idx_requests_start_ts ON requests(start_ts);
CREATE INDEX IF NOT EXISTS idx_requests_status   ON requests(status_code);
CREATE INDEX IF NOT EXISTS idx_requests_method   ON requests(method);

-- Headers exploded into rows so queries like
--   SELECT * FROM headers WHERE name_lower = 's2-db-clusterid';
-- are trivial.
CREATE TABLE IF NOT EXISTS headers (
  request_id  INTEGER NOT NULL,
  direction   TEXT    NOT NULL CHECK (direction IN ('req','resp')),
  name        TEXT    NOT NULL,
  name_lower  TEXT    NOT NULL,
  value       TEXT    NOT NULL,
  FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_headers_request_id ON headers(request_id);
CREATE INDEX IF NOT EXISTS idx_headers_name_lower ON headers(name_lower);

-- Convenience view that flattens the most commonly inspected columns.
CREATE VIEW IF NOT EXISTS v_requests AS
SELECT
  id, trace_id,
  datetime(start_ts, 'unixepoch') AS started_at,
  duration_ms,
  method, status_code,
  request_url, upstream_url,
  request_body_size, response_body_size,
  error
FROM requests;
"""


Headers = list[tuple[str, str]]


class Storage:
    """Async SQLite wrapper. All writes are serialized through one connection."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None
        # aiosqlite serializes per-connection, but we also need to bundle
        # multi-statement writes (insert + headers) atomically.
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        # Better concurrency for read-during-write (e.g. CLI list while proxy
        # is running).
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.executescript(SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Storage is not open")
        return self._db

    async def insert_pending(
        self,
        *,
        trace_id: str,
        start_ts: float,
        client_ip: str,
        method: str,
        request_url: str,
        upstream_url: str,
        request_headers: Headers,
        request_body_path: str | None,
    ) -> int:
        async with self._lock:
            cur = await self.db.execute(
                """INSERT INTO requests
                   (trace_id, start_ts, client_ip, method,
                    request_url, upstream_url,
                    request_headers_json, request_body_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    trace_id,
                    start_ts,
                    client_ip,
                    method,
                    request_url,
                    upstream_url,
                    json.dumps(request_headers),
                    request_body_path,
                ),
            )
            row_id = cur.lastrowid
            await cur.close()
            await self._insert_headers(row_id, "req", request_headers)
            await self.db.commit()
            return row_id

    async def finalize(
        self,
        row_id: int,
        *,
        end_ts: float,
        duration_ms: float,
        request_body_size: int,
        status_code: int,
        response_headers: Headers,
        response_body_path: str | None,
        response_body_size: int,
    ) -> None:
        async with self._lock:
            await self.db.execute(
                """UPDATE requests
                   SET end_ts=?, duration_ms=?, request_body_size=?,
                       status_code=?, response_headers_json=?,
                       response_body_path=?, response_body_size=?
                   WHERE id=?""",
                (
                    end_ts,
                    duration_ms,
                    request_body_size,
                    status_code,
                    json.dumps(response_headers),
                    response_body_path,
                    response_body_size,
                    row_id,
                ),
            )
            await self._insert_headers(row_id, "resp", response_headers)
            await self.db.commit()

    async def fail(
        self,
        row_id: int,
        *,
        end_ts: float,
        duration_ms: float,
        request_body_size: int,
        error: str,
    ) -> None:
        async with self._lock:
            await self.db.execute(
                """UPDATE requests
                   SET end_ts=?, duration_ms=?, request_body_size=?, error=?
                   WHERE id=?""",
                (end_ts, duration_ms, request_body_size, error, row_id),
            )
            await self.db.commit()

    async def _insert_headers(
        self, row_id: int, direction: str, headers: Iterable[tuple[str, str]]
    ) -> None:
        rows = [
            (row_id, direction, name, name.lower(), value)
            for name, value in headers
        ]
        if not rows:
            return
        await self.db.executemany(
            """INSERT INTO headers (request_id, direction, name, name_lower, value)
               VALUES (?, ?, ?, ?, ?)""",
            rows,
        )
