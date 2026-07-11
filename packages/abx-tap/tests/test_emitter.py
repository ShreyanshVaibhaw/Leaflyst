"""Emitter behavior: spool always, drain on recovery, park rejects.

Uses a local HTTP server whose behavior is switchable mid-test - this is the
"kill the backend mid-session" exit criterion in miniature.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from abx_tap.emitter import Emitter

MODE = {"value": "down"}  # down | ok | reject
RECEIVED: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if MODE["value"] == "ok":
            RECEIVED.append(json.loads(body))
            self.send_response(200)
        elif MODE["value"] == "reject":
            self.send_response(401)
        else:
            self.send_response(503)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


def start_server() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def make_event(i: int) -> dict:
    return {"n": i}


def wait_until(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_spool_survives_outage_and_drains(tmp_path: Path) -> None:
    server, url = start_server()
    MODE["value"] = "down"
    RECEIVED.clear()

    emitter = Emitter(url, "token", spool_dir=tmp_path)
    emitter.start()
    for i in range(5):
        emitter.emit(make_event(i))
    emitter.flush()

    # Backend down: spool retains the batch, nothing delivered.
    assert wait_until(lambda: list(tmp_path.glob("batch-*.json")), 5)
    time.sleep(0.5)
    assert RECEIVED == []

    # Backend recovers: spool drains.
    MODE["value"] = "ok"
    assert wait_until(lambda: not list(tmp_path.glob("batch-*.json")), 15)
    assert sum(len(r["events"]) for r in RECEIVED) == 5

    emitter.close()
    server.shutdown()


def test_rejected_batch_parked_not_looped(tmp_path: Path) -> None:
    server, url = start_server()
    MODE["value"] = "reject"

    emitter = Emitter(url, "bad-token", spool_dir=tmp_path)
    emitter.start()
    emitter.emit(make_event(1))
    emitter.flush()

    assert wait_until(lambda: list(tmp_path.glob("*.rejected")), 10)
    assert not list(tmp_path.glob("batch-*.json"))

    emitter.close()
    server.shutdown()


def test_no_backend_configured_spools_locally(tmp_path: Path) -> None:
    emitter = Emitter(None, None, spool_dir=tmp_path)
    emitter.start()
    emitter.emit(make_event(1))
    emitter.close()
    assert list(tmp_path.glob("batch-*.json"))  # kept for later, agent unaffected


def test_stale_spool_from_crashed_session_drains(tmp_path: Path) -> None:
    # A file left behind by a previous (crashed) session.
    stale = tmp_path / "batch-000-old.json"
    stale.write_text(json.dumps({"events": [make_event(9)]}), encoding="utf-8")

    server, url = start_server()
    MODE["value"] = "ok"
    RECEIVED.clear()

    emitter = Emitter(url, "token", spool_dir=tmp_path)
    emitter.start()
    assert wait_until(lambda: not list(tmp_path.glob("batch-*.json")), 10)
    assert any(e == {"n": 9} for r in RECEIVED for e in r["events"])

    emitter.close()
    server.shutdown()
