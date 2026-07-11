"""Phase 2 exit-criterion smoke: abx-tap in front of the REAL filesystem MCP
server, events landing in the live ingest and verifying, end to end.

    uv run python demo/tap_e2e_smoke.py

Requires: the dev stack up (docker compose) and node/npx on PATH.
What it does:
  1. starts the API (uvicorn) on a scratch port
  2. creates a throwaway tenant + ingest token
  3. runs `abx-tap run -- npx @modelcontextprotocol/server-filesystem <dir>`
  4. drives initialize / tools/list / tools/call through the tap
  5. asserts events arrived in ClickHouse (<60s) and the chain verifies
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import psycopg

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "apps" / "api" / "src"))

API_PORT = 8321


def wait_http(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except Exception:
            time.sleep(0.5)
    raise TimeoutError(f"{url} not reachable")


def rpc(proc: subprocess.Popen, obj: dict, expect_response: bool = True) -> dict | None:
    proc.stdin.write((json.dumps(obj) + "\n").encode())
    proc.stdin.flush()
    if not expect_response:
        return None
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("server closed stream")
    return json.loads(line)


def main() -> int:
    from abx_api.auth import new_ingest_token
    from abx_api.settings import settings
    from abx_api.store import ensure_buckets

    if not shutil.which("npx"):
        print("SKIP: npx not on PATH")
        return 0

    ensure_buckets()

    # 1. API server
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "abx_api.main:app", "--port", str(API_PORT)],
        cwd=str(REPO),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_http(f"http://127.0.0.1:{API_PORT}/healthz")

        # 2. tenant + token
        token, token_hash = new_ingest_token()
        with psycopg.connect(settings.pg_dsn) as conn:
            row = conn.execute(
                "INSERT INTO tenants (name) VALUES ('tap-smoke') RETURNING id"
            ).fetchone()
            tenant_id = str(row[0])
            conn.execute(
                "INSERT INTO ingest_tokens (tenant_id, token_hash, label) "
                "VALUES (%s, %s, 'smoke')",
                (tenant_id, token_hash),
            )
            conn.commit()

        # 3. tap in front of the real filesystem server
        workdir = tempfile.mkdtemp(prefix="abx-smoke-")
        (Path(workdir) / "hello.txt").write_text("agent was here", encoding="utf-8")
        spool = tempfile.mkdtemp(prefix="abx-spool-")
        import os

        started = time.monotonic()
        tap = subprocess.Popen(
            [
                sys.executable, "-m", "abx_tap.cli", "run",
                "--agent", "smoke-bot", "--server-name", "filesystem",
                "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", workdir,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                "ABX_INGEST_URL": f"http://127.0.0.1:{API_PORT}",
                "ABX_INGEST_TOKEN": token,
                "ABX_TAP_SPOOL_DIR": spool,
            },
            bufsize=0,
        )

        # 4. drive a real session
        init = rpc(tap, {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "abx-smoke", "version": "0"},
            },
        })
        assert "result" in init, init
        rpc(tap, {"jsonrpc": "2.0", "method": "notifications/initialized"},
            expect_response=False)
        tools = rpc(tap, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tool_names = [t["name"] for t in tools["result"]["tools"]]
        assert any("list" in t or "read" in t for t in tool_names), tool_names
        listing = rpc(tap, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_directory", "arguments": {"path": workdir}},
        })
        assert "hello.txt" in json.dumps(listing), listing

        tap.stdin.close()
        tap.wait(timeout=30)

        # 5. events in ClickHouse + chain verifies (<60s from session start)
        import clickhouse_connect

        ch = clickhouse_connect.get_client(
            host=settings.ch_host, port=settings.ch_port, database=settings.ch_database,
            username=settings.ch_user, password=settings.ch_password,
        )
        deadline = time.monotonic() + 60
        names: list[str] = []
        while time.monotonic() < deadline:
            names = [
                r[0] for r in ch.query(
                    "SELECT op_name FROM events WHERE tenant_id = %(t)s ORDER BY chain_seq",
                    parameters={"t": tenant_id},
                ).result_rows
            ]
            if any(n.startswith("tools/call") for n in names):
                break
            time.sleep(1)
        elapsed = time.monotonic() - started
        assert any(n.startswith("initialize") for n in names), names
        assert any(n.startswith("tools/list") for n in names), names
        assert any(n.startswith("tools/call list_directory") for n in names), names

        req = urllib.request.Request(
            f"http://127.0.0.1:{API_PORT}/v1/chain/verify?tenant_id={tenant_id}",
            headers={"X-Abx-Admin-Key": settings.admin_key},
        )
        with urllib.request.urlopen(req) as resp:
            verdict = json.loads(resp.read())
        assert verdict["valid"] is True, verdict

        print(f"OK: {len(names)} events from a real MCP server recorded and verified "
              f"in {elapsed:.1f}s (<60s budget)")
        print(f"    events: {names}")
        return 0
    finally:
        api.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
