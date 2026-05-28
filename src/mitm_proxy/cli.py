"""Command-line interface.

Subcommands:
  serve  - run the streaming forwarding proxy.
  list   - print recent captures with simple filters.
  show   - dump headers + paths to body files for one capture.
  body   - cat or hexdump a single request/response body to stdout.
  stats  - aggregate counts by status / method.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Iterable

import click
from aiohttp import web

from .proxy import Proxy, build_app
from .storage import Storage


DEFAULT_DATA_DIR = Path("./mitm-data")


# --------------------------------------------------------------------- helpers


def _data_dir_option(f):
    return click.option(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        type=click.Path(file_okay=False, path_type=Path),
        show_default=True,
        envvar="MITM_DATA_DIR",
        show_envvar=True,
        help="Directory containing captures.db and bodies/ subfolder.",
    )(f)


def _connect_ro(data_dir: Path) -> sqlite3.Connection:
    db_path = data_dir.expanduser() / "captures.db"
    if not db_path.exists():
        raise click.ClickException(f"No capture database at {db_path}")
    # Open read-only via URI so we don't disturb a running proxy.
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _resolve_row(conn: sqlite3.Connection, id_or_trace: str) -> sqlite3.Row:
    row: sqlite3.Row | None
    try:
        rid = int(id_or_trace)
        row = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    except ValueError:
        row = conn.execute(
            "SELECT * FROM requests WHERE trace_id = ?", (id_or_trace,)
        ).fetchone()
    if row is None:
        raise click.ClickException(f"No request found for: {id_or_trace}")
    return row


def _fmt_size(n: int | None) -> str:
    if n is None:
        return "-"
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}K"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f}M"
    return f"{n / 1024 / 1024 / 1024:.2f}G"


def _print_headers(headers_json: str | None, indent: str = "  ") -> None:
    if not headers_json:
        click.echo(f"{indent}(none)")
        return
    for name, value in json.loads(headers_json):
        click.echo(f"{indent}{name}: {value}")


# ---------------------------------------------------------------- root command


@click.group()
@click.version_option(package_name="mitm-proxy")
def main() -> None:
    """Streaming HTTP forwarding proxy with on-disk capture."""


# ----------------------------------------------------------------------- serve


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Listen host.")
@click.option("--port", default=8080, show_default=True, type=int, help="Listen port.")
@click.option(
    "--upstream",
    required=True,
    help="Upstream base URL, e.g. https://prod-nova-gateway.example.com",
)
@click.option(
    "--insecure-upstream",
    is_flag=True,
    help="Disable TLS certificate verification when calling upstream.",
)
@click.option(
    "--tcp",
    is_flag=True,
    help=(
        "Use the raw asyncio TCP proxy (byte-faithful: preserves Content-Length, "
        "reason phrase, Upgrade, trailers, 1xx interim responses; no header injection). "
        "Default is the aiohttp-based proxy."
    ),
)
@click.option(
    "--add-xff",
    is_flag=True,
    help=(
        "TCP proxy only. Append the client's IP to X-Forwarded-For so upstream "
        "can recover the originating address. Off by default since it violates "
        "the strict 'upstream sees only what client sent' contract."
    ),
)
@click.option(
    "--idle-read-timeout",
    type=float,
    default=600.0,
    show_default=True,
    envvar="MITM_IDLE_READ_TIMEOUT",
    show_envvar=True,
    help="TCP proxy only. Per-read inactivity timeout, in seconds.",
)
@click.option(
    "--upstream-connect-timeout",
    type=float,
    default=30.0,
    show_default=True,
    envvar="MITM_UPSTREAM_CONNECT_TIMEOUT",
    show_envvar=True,
    help="TCP proxy only. Upstream TCP/TLS handshake timeout, in seconds.",
)
@_data_dir_option
def serve(
    host: str,
    port: int,
    upstream: str,
    insecure_upstream: bool,
    tcp: bool,
    add_xff: bool,
    idle_read_timeout: float,
    upstream_connect_timeout: float,
    data_dir: Path,
) -> None:
    """Start the forwarding proxy."""
    data_dir = data_dir.expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    if tcp:
        from .tcp_proxy import run as run_tcp

        click.echo(f"[mitm-proxy] (tcp) listening on http://{host}:{port}  ->  {upstream}")
        if add_xff:
            click.echo("[mitm-proxy] injecting X-Forwarded-For header")
        click.echo(f"[mitm-proxy] capturing to {data_dir}")
        try:
            asyncio.run(
                run_tcp(
                    host=host,
                    port=port,
                    upstream=upstream,
                    verify_tls=not insecure_upstream,
                    data_dir=data_dir,
                    add_xff=add_xff,
                    idle_read_timeout=idle_read_timeout,
                    upstream_connect_timeout=upstream_connect_timeout,
                )
            )
        except KeyboardInterrupt:
            pass
        return

    storage = Storage(data_dir / "captures.db")
    proxy = Proxy(
        upstream=upstream,
        storage=storage,
        bodies_dir=data_dir / "bodies",
        verify_tls=not insecure_upstream,
    )

    async def open_storage(_app):
        await storage.open()

    async def close_storage(_app):
        await storage.close()

    app = build_app(proxy)
    # Storage open/close must wrap proxy startup/cleanup.
    app.on_startup.insert(0, open_storage)
    app.on_cleanup.append(close_storage)

    click.echo(f"[mitm-proxy] listening on http://{host}:{port}  ->  {upstream}")
    click.echo(f"[mitm-proxy] capturing to {data_dir}")
    web.run_app(app, host=host, port=port, print=lambda *_: None)


# ------------------------------------------------------------------------ list


@main.command(name="list")
@_data_dir_option
@click.option("--limit", default=20, show_default=True, type=int)
@click.option("--method", help="Filter by HTTP method (case-insensitive).")
@click.option("--status", type=int, help="Filter by exact status code.")
@click.option("--min-status", type=int, help="status_code >= this.")
@click.option("--max-status", type=int, help="status_code <= this.")
@click.option("--path-like", help="SQL LIKE pattern on request_url (e.g. %%/pythonudfs/%%).")
@click.option("--errors-only", is_flag=True, help="Only show rows with an error or 5xx.")
def list_cmd(
    data_dir: Path,
    limit: int,
    method: str | None,
    status: int | None,
    min_status: int | None,
    max_status: int | None,
    path_like: str | None,
    errors_only: bool,
) -> None:
    """List recent captures (newest first)."""
    conn = _connect_ro(data_dir)
    where: list[str] = ["1=1"]
    args: list[object] = []
    if method:
        where.append("method = ?")
        args.append(method.upper())
    if status is not None:
        where.append("status_code = ?")
        args.append(status)
    if min_status is not None:
        where.append("status_code >= ?")
        args.append(min_status)
    if max_status is not None:
        where.append("status_code <= ?")
        args.append(max_status)
    if path_like:
        where.append("request_url LIKE ?")
        args.append(path_like)
    if errors_only:
        where.append("(error IS NOT NULL OR status_code >= 500)")
    args.append(limit)

    sql = (
        "SELECT id, trace_id, start_ts, duration_ms, method, status_code, "
        "request_url, request_body_size, response_body_size, error "
        f"FROM requests WHERE {' AND '.join(where)} "
        "ORDER BY id DESC LIMIT ?"
    )

    fmt = "{id:>5}  {method:<6}  {status:>3}  {dur:>8}  {req:>7}  {resp:>7}  {url}"
    click.echo(
        fmt.format(
            id="id", method="meth", status="sc", dur="ms",
            req="req", resp="resp", url="url",
        )
    )
    click.echo("-" * 100)
    for row in conn.execute(sql, args):
        click.echo(
            fmt.format(
                id=row["id"],
                method=row["method"],
                status=row["status_code"] if row["status_code"] is not None else "-",
                dur=f"{row['duration_ms']:.1f}" if row["duration_ms"] is not None else "-",
                req=_fmt_size(row["request_body_size"]),
                resp=_fmt_size(row["response_body_size"]),
                url=(row["request_url"][:80] + "…") if len(row["request_url"]) > 80 else row["request_url"],
            )
        )
        if row["error"]:
            click.echo(f"        ERROR: {row['error']}")


# ------------------------------------------------------------------------ show


@main.command()
@_data_dir_option
@click.argument("id_or_trace")
def show(data_dir: Path, id_or_trace: str) -> None:
    """Show full headers + body file paths for one capture."""
    data_dir = data_dir.expanduser()
    conn = _connect_ro(data_dir)
    row = _resolve_row(conn, id_or_trace)
    bodies_dir = data_dir / "bodies"

    click.echo(f"id          : {row['id']}")
    click.echo(f"trace_id    : {row['trace_id']}")
    click.echo(f"started_at  : {row['start_ts']}")
    click.echo(f"duration_ms : {row['duration_ms']}")
    click.echo(f"client_ip   : {row['client_ip']}")
    click.echo(f"request     : {row['method']} {row['request_url']}")
    click.echo(f"upstream    : {row['upstream_url']}")
    click.echo(f"status      : {row['status_code']}")
    if row["error"]:
        click.echo(f"error       : {row['error']}")

    click.echo("\n--- Request Headers ---")
    _print_headers(row["request_headers_json"])
    click.echo(
        f"\n--- Request Body  ({_fmt_size(row['request_body_size'])}) ---"
    )
    if row["request_body_path"]:
        click.echo(f"  {bodies_dir / row['request_body_path']}")
    else:
        click.echo("  (no body)")

    click.echo("\n--- Response Headers ---")
    _print_headers(row["response_headers_json"])
    click.echo(
        f"\n--- Response Body ({_fmt_size(row['response_body_size'])}) ---"
    )
    if row["response_body_path"]:
        click.echo(f"  {bodies_dir / row['response_body_path']}")
    else:
        click.echo("  (no body)")


# ------------------------------------------------------------------------ body


@main.command()
@_data_dir_option
@click.argument("id_or_trace")
@click.option(
    "--direction",
    type=click.Choice(["req", "resp"]),
    default="resp",
    show_default=True,
)
def body(data_dir: Path, id_or_trace: str, direction: str) -> None:
    """Stream a captured body to stdout."""
    data_dir = data_dir.expanduser()
    conn = _connect_ro(data_dir)
    row = _resolve_row(conn, id_or_trace)
    path_col = "request_body_path" if direction == "req" else "response_body_path"
    name = row[path_col]
    if not name:
        raise click.ClickException(f"No {direction} body for {id_or_trace}")
    body_path = data_dir / "bodies" / name
    if not body_path.exists():
        raise click.ClickException(f"Body file missing: {body_path}")
    with body_path.open("rb") as f:
        shutil.copyfileobj(f, sys.stdout.buffer)


# ----------------------------------------------------------------------- stats


@main.command()
@_data_dir_option
def stats(data_dir: Path) -> None:
    """Aggregate counts by method and status code."""
    conn = _connect_ro(data_dir)
    total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    click.echo(f"total: {total}")
    click.echo("\nby method:")
    for row in conn.execute(
        "SELECT method, COUNT(*) AS n FROM requests GROUP BY method ORDER BY n DESC"
    ):
        click.echo(f"  {row['method']:<8} {row['n']}")
    click.echo("\nby status:")
    for row in conn.execute(
        "SELECT status_code, COUNT(*) AS n FROM requests "
        "GROUP BY status_code ORDER BY status_code"
    ):
        click.echo(f"  {row['status_code'] if row['status_code'] is not None else 'ERR':<8} {row['n']}")
    click.echo("\nslowest 5:")
    for row in conn.execute(
        "SELECT id, method, status_code, duration_ms, request_url FROM requests "
        "WHERE duration_ms IS NOT NULL ORDER BY duration_ms DESC LIMIT 5"
    ):
        click.echo(
            f"  #{row['id']:<5} {row['method']:<6} {row['status_code']!s:<4} "
            f"{row['duration_ms']:>8.1f}ms  {row['request_url']}"
        )


if __name__ == "__main__":  # pragma: no cover
    main()
