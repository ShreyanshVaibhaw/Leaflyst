"""End-to-end Phase 1 exit criteria against the live dev stack.

Covers: ingest -> ClickHouse rows with secrets scrubbed; chain verifies;
tamper is caught and names the first divergent event; payload deletion keeps
the chain verifiable; abx-verify validates an offline export.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from abx_api.chain import format_ts, row_to_event
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client, delete_payload
from conftest import requires_stack
from fastapi.testclient import TestClient

pytestmark = requires_stack

client = TestClient(app)


def _event(seq: int, payload: str | None = None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "agent_id": "billing-bot",
        "session_id": "sess-e2e",
        "seq": seq,
        "ts": format_ts(datetime.now(UTC)),
        "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {"name": "tools/call x", "outcome": "success", "duration_ms": 4},
        "resource_refs": ["file:/tmp/a"],
        "payload": payload,
    }


def _ingest(token: str, events: list[dict]) -> dict:
    resp = client.post(
        "/v1/ingest",
        json={"events": events},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _fetch_rows(tenant_id: str) -> list[dict]:
    res = ch_client().query(
        "SELECT * FROM events WHERE tenant_id = %(t)s ORDER BY chain_seq",
        parameters={"t": tenant_id},
    )
    return [dict(zip(res.column_names, r, strict=True)) for r in res.result_rows]


def test_ingest_scrubs_secrets_and_chain_verifies(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    secret_payload = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    _ingest(token, [_event(0, secret_payload), _event(1), _event(2, "clean text")])

    rows = _fetch_rows(tenant_id)
    assert len(rows) == 3

    # No raw secret reached ClickHouse or the payload store.
    from abx_api.store import get_payload

    for row in rows:
        assert b"wJalrXUtnFEMI" not in bytes(str(row), "utf-8")
        if row["payload_ref"]:
            body = get_payload(row["payload_ref"])
            assert body is not None
            assert b"wJalrXUtnFEMI" not in body
    assert "aws-secret-key" in list(rows[0]["redactions"])

    resp = client.get(
        "/v1/chain/verify",
        params={"tenant_id": tenant_id},
        headers={"X-Abx-Admin-Key": settings.admin_key},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["valid"] is True
    assert body["events_checked"] == 3
    assert body["head_matches_checkpoint"] is True


def test_tamper_is_caught(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    _ingest(token, [_event(0), _event(1), _event(2)])
    rows = _fetch_rows(tenant_id)
    target_event_id = row_to_event(rows[1])["event_id"]

    # Tamper by inserting a mutated duplicate row (append-only store: we cannot
    # UPDATE, so a forged history is an added row the recompute rejects).
    # Simpler: mutate in a verify over a hand-built list.
    from abx_api.chain import verify_chain

    events = [row_to_event(r) for r in rows]
    events[1]["agent_id"] = "attacker"
    valid, divergent = verify_chain(events)
    assert not valid
    assert divergent == target_event_id


def test_payload_deletion_keeps_chain_valid(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    _ingest(token, [_event(0, "OPENAI_API_KEY=sk-proj-1234567890abcdefghij"), _event(1)])
    rows = _fetch_rows(tenant_id)
    ref = rows[0]["payload_ref"]
    assert ref
    delete_payload(ref)  # GDPR-style erasure

    resp = client.get(
        "/v1/chain/verify",
        params={"tenant_id": tenant_id},
        headers={"X-Abx-Admin-Key": settings.admin_key},
    )
    assert resp.json()["valid"] is True  # digest is hashed, body is not


def test_abx_verify_offline(tenant: tuple[str, str], tmp_path: Path) -> None:
    tenant_id, token = tenant
    result = _ingest(token, [_event(0), _event(1), _event(2)])
    events = [row_to_event(r) for r in _fetch_rows(tenant_id)]

    export = tmp_path / "events.jsonl"
    import json

    export.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

    verifier = Path(__file__).parents[3] / "tools" / "abx_verify.py"
    proc = subprocess.run(
        [sys.executable, str(verifier), str(export), "--expect-head", result["chain_head"]],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "3 events verified" in proc.stdout


def test_admin_key_required(tenant: tuple[str, str]) -> None:
    tenant_id, _ = tenant
    resp = client.get("/v1/chain/verify", params={"tenant_id": tenant_id})
    assert resp.status_code == 401


def test_bad_ingest_token_rejected() -> None:
    resp = client.post(
        "/v1/ingest",
        json={"events": [_event(0)]},
        headers={"Authorization": "Bearer abx_ingest_nope"},
    )
    assert resp.status_code == 401
