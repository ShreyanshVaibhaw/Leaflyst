"""Pump end-to-end: the tap as a real subprocess in front of a real (fake)
stdio MCP server. Exercises byte-faithful passthrough, spool capture, exit
code propagation, and the <20ms added-latency exit criterion.
"""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

FAKE_SERVER = str(Path(__file__).parent / "fake_mcp_server.py")


def start_tap(spool_dir: Path) -> subprocess.Popen:
    import os

    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "ABX_TAP_SPOOL_DIR": str(spool_dir),
        # No ingest backend: events spool locally (never blocks the agent).
    }
    cmd = [
        sys.executable, "-m", "abx_tap.cli", "run",
        "--agent", "e2e-agent", "--server-name", "fake",
        "--", sys.executable, "-u", FAKE_SERVER,
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, bufsize=0,
    )
    assert proc.stdin and proc.stdout
    return proc


def rpc(proc: subprocess.Popen, obj: dict) -> dict:
    line = (json.dumps(obj) + "\n").encode()
    proc.stdin.write(line)
    proc.stdin.flush()
    resp = proc.stdout.readline()
    return json.loads(resp)


def drain_notification(proc: subprocess.Popen) -> dict:
    return json.loads(proc.stdout.readline())


def test_passthrough_and_exit_code(tmp_path: Path) -> None:
    proc = start_tap(tmp_path)
    try:
        init = rpc(proc, {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                          "params": {"protocolVersion": "2025-11-25", "capabilities": {}}})
        assert init["result"]["protocolVersion"] == "2025-11-25"
        note = drain_notification(proc)
        assert note["method"] == "notifications/initialized-ack"

        tools = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert [t["name"] for t in tools["result"]["tools"]] == ["echo", "read_file"]

        call = rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": "echo", "arguments": {"path": "/tmp/f"}}})
        assert call["result"]["content"][0]["text"] == json.dumps({"path": "/tmp/f"})

        err = rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "bogus/method"})
        assert err["error"]["code"] == -32601
    finally:
        proc.stdin.close()
        assert proc.wait(timeout=10) == 0  # child exit code propagated

    # Events were captured to the spool (no backend configured).
    batches = list(tmp_path.glob("batch-*.json"))
    assert batches
    events = [e for b in batches for e in json.loads(b.read_text())["events"]]
    names = [e["operation"]["name"] for e in events]
    assert any(n.startswith("tools/call") for n in names)
    assert any(n.startswith("initialize") for n in names)
    assert all(e["source"] == "mcp_tap" for e in events)


def test_unparseable_lines_pass_through(tmp_path: Path) -> None:
    # The fake server would crash on non-JSON; use a cat-like echo child so we
    # verify raw bytes cross the tap untouched in both directions.
    import os

    cmd = [
        sys.executable, "-m", "abx_tap.cli", "run", "--agent", "x",
        "--", sys.executable, "-c",
        "import sys\n"
        "for l in sys.stdin.buffer: sys.stdout.buffer.write(l); sys.stdout.buffer.flush()",
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ}, bufsize=0,
    )
    raw = b'this is { not json \xf0\x9f\x91\x8d\n'
    proc.stdin.write(raw)
    proc.stdin.flush()
    assert proc.stdout.readline() == raw  # byte-identical passthrough
    proc.stdin.close()
    proc.wait(timeout=10)


def test_latency_overhead_under_20ms(tmp_path: Path) -> None:
    proc = start_tap(tmp_path)
    try:
        rpc(proc, {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                   "params": {"protocolVersion": "2025-11-25", "capabilities": {}}})
        drain_notification(proc)

        samples = []
        for i in range(200):
            start = time.perf_counter()
            rpc(proc, {"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                       "params": {"name": "echo", "arguments": {"i": i}}})
            samples.append((time.perf_counter() - start) * 1000)

        p95 = statistics.quantiles(samples, n=20)[-1]
        # Round trip THROUGH tap and server; tap overhead is a subset of this.
        assert p95 < 20, f"p95 round trip {p95:.2f}ms exceeds 20ms budget"
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
