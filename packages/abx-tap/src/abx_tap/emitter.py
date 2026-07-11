"""Spooled event delivery: batch -> disk spool -> background POST with retry.

The invariant (blueprint 5.1): the tap NEVER blocks or breaks the agent.
Every batch is written to a local spool file first; a sender thread ships
spool files to /v1/ingest and deletes them on success. If the backend is
down, spool files accumulate and drain on recovery - including files left by
crashed sessions, which the sender also picks up.

stdlib-only (urllib): the tap must stay dependency-free.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


def default_spool_dir() -> Path:
    return Path(
        os.environ.get("ABX_TAP_SPOOL_DIR", str(Path.home() / ".abx-tap" / "spool"))
    )
FLUSH_INTERVAL_S = 2.0
FLUSH_AT_EVENTS = 200
SEND_TIMEOUT_S = 10


def _log(msg: str) -> None:
    """Diagnostics go to a log file, NEVER stdout (stdout is MCP traffic)."""
    try:
        log_dir = default_spool_dir().parent
        log_dir.mkdir(parents=True, exist_ok=True)
        with open(log_dir / "tap.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}\n")
    except OSError:
        pass


class Emitter:
    def __init__(
        self,
        ingest_url: str | None,
        ingest_token: str | None,
        spool_dir: Path | None = None,
    ) -> None:
        self.ingest_url = ingest_url
        self.ingest_token = ingest_token
        self.spool_dir = spool_dir if spool_dir is not None else default_spool_dir()
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sender = threading.Thread(target=self._sender_loop, daemon=True)
        if not (ingest_url and ingest_token):
            _log("no ingest url/token configured; events spool locally only")

    def start(self) -> None:
        self._sender.start()

    def emit(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= FLUSH_AT_EVENTS:
                self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        path = self.spool_dir / f"batch-{time.time_ns()}-{uuid.uuid4().hex[:8]}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps({"events": self._buffer}), encoding="utf-8")
            os.replace(tmp, path)  # atomic: sender never sees partial files
            self._buffer = []
        except OSError as e:
            _log(f"spool write failed: {e}")

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def close(self) -> None:
        """Final flush and a bounded best-effort drain (agent is exiting)."""
        self.flush()
        self._stop.set()
        self._sender.join(timeout=1)
        self._try_send_all(deadline=time.monotonic() + 5)

    # -- sender thread --------------------------------------------------

    def _sender_loop(self) -> None:
        backoff = 1.0
        while not self._stop.wait(FLUSH_INTERVAL_S):
            self.flush()
            ok = self._try_send_all(deadline=time.monotonic() + 30)
            backoff = 1.0 if ok else min(backoff * 2, 60)
            if not ok:
                self._stop.wait(backoff)

    def _try_send_all(self, deadline: float) -> bool:
        """Send every spool file (oldest first, any session). True if clean."""
        if not (self.ingest_url and self.ingest_token):
            return True
        try:
            files = sorted(self.spool_dir.glob("batch-*.json"))
        except OSError:
            return True
        for path in files:
            if time.monotonic() > deadline:
                return False
            if not self._send_file(path):
                return False
        return True

    def _send_file(self, path: Path) -> bool:
        assert self.ingest_url and self.ingest_token
        try:
            body = path.read_bytes()
        except OSError:
            return True  # another process took it
        req = urllib.request.Request(
            self.ingest_url.rstrip("/") + "/v1/ingest",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.ingest_token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=SEND_TIMEOUT_S) as resp:
                if resp.status == 200:
                    path.unlink(missing_ok=True)
                    return True
                _log(f"ingest returned {resp.status} for {path.name}")
                return False
        except urllib.error.HTTPError as e:
            if 400 <= e.code < 500 and e.code != 429:
                # Permanently rejected (bad token/shape): park it, don't loop.
                _log(f"ingest rejected {path.name} with {e.code}; parking")
                path.rename(path.with_suffix(".rejected"))
                return True
            _log(f"ingest HTTP {e.code} for {path.name}; will retry")
            return False
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            _log(f"ingest unreachable ({e}); will retry")
            return False
