"""Phase 8 report check: a real Next route returns Markdown and a Chromium PDF."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

from abx_api.main import app
from fastapi.testclient import TestClient
from self_serve_smoke import HEADERS, _cleanup

API_PORT = 8432
WEB_PORT = 3432
REPO = Path(__file__).resolve().parent.parent


def _wait(url: str, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except Exception:
            time.sleep(0.5)
    raise TimeoutError(f"{url} did not become ready")


def _read(url: str, timeout: float) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read()
    except HTTPError as exc:
        message = exc.read().decode(errors="replace")
        raise RuntimeError(f"{url} returned {exc.code}: {message}") from exc


def main() -> int:
    if not shutil.which("node"):
        print("SKIP: node is not available")
        return 0
    user_ref = f"report-smoke-{time.time_ns()}"
    client = TestClient(app)
    bootstrap = client.post(
        "/v1/onboarding/bootstrap",
        headers=HEADERS,
        json={"user_ref": user_ref, "tenant_name": "Report Smoke"},
    )
    bootstrap.raise_for_status()
    owner_tenant_id = bootstrap.json()["tenant_id"]
    import abx_api.demo

    abx_api.demo.settings = SimpleNamespace(demo_enabled=True)
    demo = client.post("/v1/demo/run", params={"tenant_id": owner_tenant_id}, headers=HEADERS)
    demo.raise_for_status()
    tenant_id = demo.json()["tenant_id"]
    session_id = demo.json()["session_id"]
    env = {
        **os.environ,
        "ABX_API_URL": f"http://127.0.0.1:{API_PORT}",
        "ABX_TENANT_ID": tenant_id,
        "ABX_CHROMIUM_CHANNEL": "msedge",
    }
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "abx_api.main:app", "--port", str(API_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd=REPO,
    )
    web = None
    try:
        _wait(f"http://127.0.0.1:{API_PORT}/healthz")
        web = subprocess.Popen(
            [
                shutil.which("node") or "node",
                str(REPO / "apps" / "web" / "node_modules" / "next" / "dist" / "bin" / "next"),
                "dev",
                "-p",
                str(WEB_PORT),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=REPO / "apps" / "web",
        )
        _wait(f"http://127.0.0.1:{WEB_PORT}/security", timeout=120)
        base = f"http://127.0.0.1:{WEB_PORT}/api/exports/sessions/{session_id}/report"
        markdown = _read(f"{base}/md", 30)
        pdf = _read(f"{base}/pdf", 60)
        assert markdown.startswith(b"# Leaflyst Incident Report")
        assert b"Chain verification" in markdown
        assert pdf.startswith(b"%PDF-") and len(pdf) > 10_000
        print(f"OK: valid Markdown ({len(markdown)} bytes) and PDF ({len(pdf)} bytes)")
        return 0
    finally:
        if web is not None:
            web.terminate()
        api.terminate()
        _cleanup(owner_tenant_id)


if __name__ == "__main__":
    raise SystemExit(main())
