"""Replay timeline, blast radius, sharing, joins, and visible tamper evidence."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import EVENT_COLUMNS, ch_client
from conftest import requires_stack
from fastapi.testclient import TestClient

pytestmark = requires_stack
client = TestClient(app)
ADMIN = {"X-Abx-Admin-Key": settings.admin_key}


def _event(session_id: str, seq: int, credential_ref: str) -> dict[str, object]:
    return {
        "event_id": str(uuid.uuid4()), "agent_id": "checkout-agent",
        "session_id": session_id, "seq": seq, "ts": datetime.now(UTC).isoformat(),
        "source": "mcp_tap", "event_type": "tool_call",
        "operation": {"name": "write order", "provider": "aws", "target": "orders",
                      "outcome": "success", "duration_ms": 14},
        "credential_ref": credential_ref,
        "resource_refs": ["aws:dynamodb:orders", "gh:repo:acme/checkout"],
        "payload": "<script>window.pwned=true</script> secret ghp_" + "a" * 36,
    }


def test_replay_blast_radius_share_and_credential_join(
    tenant: tuple[str, str],
) -> None:
    tenant_id, token = tenant
    fingerprint = "AKIA1234567890ABCDEF"
    with psycopg.connect(settings.pg_dsn) as conn:
        credential_id = str(conn.execute(
            "INSERT INTO credentials (tenant_id, provider, kind, fingerprint) "
            "VALUES (%s, 'aws', 'access_key', %s) RETURNING id",
            (tenant_id, fingerprint),
        ).fetchone()[0])
    session_id = "session-replay-test"
    response = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [_event(session_id, 0, fingerprint),
                         _event(session_id, 2, fingerprint)]},
    )
    assert response.status_code == 200, response.text

    replay = client.get(
        f"/v1/replay/sessions/{session_id}",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    )
    assert replay.status_code == 200, replay.text
    body = replay.json()
    assert body["verification"]["valid"] is True
    assert [item["kind"] for item in body["timeline"]] == ["event", "gap", "event"]
    assert body["timeline"][1]["missing_count"] == 1
    assert "ghp_" not in body["timeline"][0]["payload"]
    assert "<script>" in body["timeline"][0]["payload"]  # escaped by React, never executed
    assert {item["resource_ref"] for item in body["blast_radius"]} == {
        "aws:dynamodb:orders", "gh:repo:acme/checkout",
    }
    assert body["blast_radius"][0]["credentials"][0]["id"] == credential_id

    credential_events = client.get(
        f"/v1/replay/credentials/{credential_id}/events",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    ).json()
    assert len(credential_events) == 2
    assert credential_events[0]["session_id"] == session_id

    created = client.post(
        f"/v1/replay/sessions/{session_id}/share",
        params={"tenant_id": tenant_id}, headers=ADMIN,
        json={"expires_in_hours": 1},
    )
    assert created.status_code == 200
    share_token = created.json()["token"]
    shared = client.get(f"/v1/replay/shared/{share_token}")
    assert shared.status_code == 200
    assert shared.json()["read_only"] is True
    with psycopg.connect(settings.pg_dsn) as conn:
        stored = conn.execute(
            "SELECT token_hash FROM session_shares WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()[0]
    assert stored == hashlib.sha256(share_token.encode()).hexdigest()
    assert share_token not in stored


def test_tamper_flips_session_verification_badge(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    session_id = "session-tamper-test"
    assert client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [_event(session_id, 0, "AKIA1234567890ABCDEF")]},
    ).status_code == 200
    result = ch_client().query(
        f"SELECT {', '.join(EVENT_COLUMNS)} FROM events "
        "WHERE tenant_id = %(tenant)s AND session_id = %(session)s",
        parameters={"tenant": tenant_id, "session": session_id},
    )
    forged = list(result.result_rows[0])
    forged[0] = uuid.uuid4()
    forged[20] = b"0" * 64
    forged[21] = int(forged[21]) + 100
    ch_client().insert("events", [forged], column_names=EVENT_COLUMNS)
    replay = client.get(
        f"/v1/replay/sessions/{session_id}",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    )
    assert replay.status_code == 200
    assert replay.json()["verification"]["valid"] is False


def test_sessions_can_be_listed_for_a_named_agent(tenant: tuple[str, str]) -> None:
    """Agents are named, not numbered, and this route had two defects at once.

    The ClickHouse query aliased an aggregate as `agent_id` and then filtered on
    an unqualified `agent_id`, so the server resolved the WHERE reference to the
    aggregate and rejected every call with ILLEGAL_AGGREGATION. That 500 was
    then mistaken for a malformed-identifier fault and "fixed" by constraining
    the path parameter to a UUID, which left the SQL bug in place and rejected
    every real agent name with 422.

    The route had tests. None of them called it, which is the only reason a
    route that answered 500 unconditionally could sit there.
    """
    tenant_id, token = tenant
    session_id = "session-named-agent"
    ingested = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [_event(session_id, 0, "AKIA1234567890ABCDEF")]},
    )
    assert ingested.status_code == 200, ingested.text

    listed = client.get(
        "/v1/replay/agents/checkout-agent/sessions",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    )
    assert listed.status_code == 200, listed.text
    sessions = listed.json()
    assert [item["session_id"] for item in sessions] == [session_id]
    assert sessions[0]["agent_id"] == "checkout-agent"
    assert sessions[0]["event_count"] == 1

    # An agent that does not exist is an empty list, not an error and not a leak.
    absent = client.get(
        "/v1/replay/agents/no-such-agent/sessions",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    )
    assert absent.status_code == 200, absent.text
    assert absent.json() == []
