"""Ingest throughput check: sustain >=10k events/min on one node (blueprint #3).

Marked 'load' so it is opt-in: run with `uv run pytest -m load`.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import pytest
from abx_api.chain import format_ts
from abx_api.main import app
from conftest import requires_stack
from fastapi.testclient import TestClient

pytestmark = [requires_stack, pytest.mark.load]

TARGET_PER_MIN = 10_000


def _batch(n: int) -> dict:
    now = format_ts(datetime.now(UTC))
    return {
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "agent_id": "load-bot",
                "session_id": "sess-load",
                "seq": i,
                "ts": now,
                "source": "mcp_tap",
                "event_type": "mcp_request",
                "operation": {"name": "tools/call x", "outcome": "success"},
                "resource_refs": ["file:/tmp/a"],
                "payload": "some tool output with no secrets " * 5,
            }
            for i in range(n)
        ]
    }


def test_throughput(tenant: tuple[str, str]) -> None:
    _, token = tenant
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    total = 2_000
    per_batch = 200

    start = time.perf_counter()
    sent = 0
    while sent < total:
        resp = client.post("/v1/ingest", json=_batch(per_batch), headers=headers)
        assert resp.status_code == 200, resp.text
        sent += per_batch
    elapsed = time.perf_counter() - start

    rate_per_min = sent / elapsed * 60
    print(f"\ningested {sent} events in {elapsed:.2f}s = {rate_per_min:,.0f}/min")
    assert rate_per_min >= TARGET_PER_MIN, f"{rate_per_min:,.0f}/min below target"
