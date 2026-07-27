from __future__ import annotations

import threading
from pathlib import Path
from runpy import run_path

import httpx

_tool = run_path(str(Path(__file__).parents[3] / "tools" / "http_load.py"))
Config = _tool["Config"]
run_load = _tool["run_load"]


def test_real_network_load_accounting_and_chain_verification() -> None:
    lock = threading.Lock()
    stored = 3

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal stored
        if request.url.path == "/v1/chain/verify":
            return httpx.Response(200, json={"valid": True, "events_checked": stored})
        events = request.read()
        count = len(httpx.Response(200, content=events).json()["events"])
        with lock:
            stored += count
        return httpx.Response(200, json={"accepted": count})

    with httpx.Client(
        transport=httpx.MockTransport(handle), base_url="http://leaflyst.test"
    ) as client:
        result = run_load(
            client,
            "write-only-token",
            Config(
                rate_per_minute=6_000,
                duration_seconds=0.1,
                batch_size=4,
                payload_bytes=16,
                concurrency=2,
                tenant_id="dedicated-load-tenant",
                admin_key="admin-key",
            ),
        )

    assert result.ok
    assert result.requested == result.accepted == 10
    assert result.rate_target_met
    assert result.chain_events_after == result.chain_events_before + result.accepted
