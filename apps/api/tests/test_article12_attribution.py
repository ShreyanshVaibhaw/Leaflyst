"""EU AI Act Article 12: operator attribution and the retention floor.

Article 12 requires identifying the natural persons involved and retaining the
record for at least six months. Two design decisions are under test here, and
both are security properties rather than features:

1. The operator is bound to the ingest TOKEN, never taken from the event body.
   A write-only recording token is held by an agent the product explicitly does
   not trust to be honest (guiding constraint 1), so a self-declared operator
   would be forgeable and worthless as evidence.

2. A tenant in compliance mode cannot lower retention below the floor by any
   API path, and the refused attempt is itself chained.
"""

from __future__ import annotations

import uuid

from abx_api.chain import row_to_event, verify_chain
from abx_api.ingest import ingest_events
from abx_api.main import app
from abx_api.store import ch_client, pg_pool
from abx_api.tenant_settings import operator_fingerprint
from abx_schemas import IngestEvent
from abx_schemas.generated.contract import CURRENT_SCHEMA_VERSION
from conftest import requires_stack
from fastapi.testclient import TestClient


def fetch_session_events(tenant_id: str, session_id: str) -> list[dict]:
    """Canonical events for one session, in chain order."""
    rows = ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(t)s AND session_id=%(s)s ORDER BY chain_seq",
        parameters={"t": tenant_id, "s": session_id},
    ).named_results()
    return [row_to_event(dict(row)) for row in rows]


def an_event(session_id: str) -> IngestEvent:
    return IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "agent-a", "session_id": session_id,
        "seq": 0, "ts": "2026-07-30T12:00:00.000Z", "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {"name": "tools/call echo", "outcome": "success"},
        "resource_refs": [],
    })


@requires_stack
def test_events_record_the_operator_bound_to_the_token(tenant) -> None:
    tenant_id, _ = tenant
    session_id = f"attributed-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)], operator_ref="operator-alice")

    events = fetch_session_events(tenant_id, session_id)
    assert events, "session should have recorded"
    assert events[0]["operator_ref"] == "operator-alice"
    assert events[0]["schema_version"] == CURRENT_SCHEMA_VERSION


@requires_stack
def test_attributed_events_still_verify_end_to_end(tenant) -> None:
    """The attribution is inside the hashed field set, so a round trip through
    ClickHouse has to reproduce it byte-exactly or the chain breaks."""
    tenant_id, _ = tenant
    session_id = f"verify-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)], operator_ref="operator-bob")

    events = fetch_session_events(tenant_id, session_id)
    valid, divergent = verify_chain(events)
    assert valid and divergent is None


@requires_stack
def test_unattributed_recording_is_explicit_not_guessed(tenant) -> None:
    """A token minted before operator binding records with no operator. That
    must read as an explicit null so the evidence pack can report it as
    unattributed, rather than being silently ascribed to someone."""
    tenant_id, _ = tenant
    session_id = f"unattributed-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)])

    events = fetch_session_events(tenant_id, session_id)
    assert events[0]["operator_ref"] is None
    assert events[0]["schema_version"] == CURRENT_SCHEMA_VERSION
    valid, _ = verify_chain(events)
    assert valid


@requires_stack
def test_ingest_body_cannot_assert_an_operator(tenant) -> None:
    """The agent must not be able to name the human it is recorded against."""
    tenant_id, token = tenant
    session_id = f"forged-{uuid.uuid4()}"
    body = an_event(session_id).model_dump(mode="json")
    body["operator_ref"] = "someone-important"

    client = TestClient(app)
    response = client.post(
        "/v1/ingest",
        json={"events": [body]},
        headers={"Authorization": f"Bearer {token}"},
    )
    # The producer contract has no operator field at all, so an attempt to
    # supply one is rejected outright rather than quietly dropped.
    assert response.status_code == 422

    events = fetch_session_events(tenant_id, session_id)
    assert events == []


@requires_stack
def test_token_creation_binds_its_operator(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    response = client.post(
        f"/v1/settings/tokens?tenant_id={tenant_id}",
        json={"kind": "recording", "label": "ci", "operator_user_ref": "user_alice"},
        headers={"X-Abx-Admin-Key": "dev-admin-key"},
    )
    assert response.status_code == 200, response.text
    token_id = response.json()["id"]

    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT o.user_ref,o.email_fingerprint FROM ingest_tokens i "
            "JOIN operators o ON o.id=i.operator_id WHERE i.id=%s",
            (token_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == "user_alice"
    # The identity itself is never stored in the clear.
    assert row[1] == operator_fingerprint("user_alice")
    assert "user_alice" not in row[1]


@requires_stack
def test_compliance_mode_refuses_retention_below_the_floor(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    admin = {"X-Abx-Admin-Key": "dev-admin-key"}
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "compliance_mode,retention_floor_days) VALUES (%s,365,TRUE,TRUE,180) "
            "ON CONFLICT (tenant_id) DO UPDATE SET retention_days=365,"
            "compliance_mode=TRUE,retention_floor_days=180",
            (tenant_id,),
        )

    response = client.put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "t", "retention_days": 30, "capture_payloads": True},
        headers=admin,
    )
    assert response.status_code == 409
    assert "180-day compliance floor" in response.json()["detail"]

    # The floor held.
    current = client.get(f"/v1/settings?tenant_id={tenant_id}", headers=admin).json()
    assert current["retention_days"] == 365
    assert current["compliance_mode"] is True
    assert current["retention_floor_days"] == 180


@requires_stack
def test_a_refused_retention_change_is_itself_recorded(tenant) -> None:
    """An audit trail that silently drops failed policy changes is not an audit
    trail: an auditor must be able to see that someone tried."""
    tenant_id, _ = tenant
    client = TestClient(app)
    admin = {"X-Abx-Admin-Key": "dev-admin-key"}
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "compliance_mode,retention_floor_days) VALUES (%s,365,TRUE,TRUE,180) "
            "ON CONFLICT (tenant_id) DO UPDATE SET retention_days=365,"
            "compliance_mode=TRUE,retention_floor_days=180",
            (tenant_id,),
        )

    client.put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "t", "retention_days": 7, "capture_payloads": True},
        headers=admin,
    )

    rows = ch_client().query(
        "SELECT op_name,op_outcome,resource_refs FROM events "
        "WHERE tenant_id=%(t)s AND op_name='retention change refused'",
        parameters={"t": tenant_id},
    ).result_rows
    assert rows, "the refused attempt should be in the tenant chain"
    assert rows[0][1] == "denied"
    assert "abx:retention-floor:180" in list(rows[0][2])


@requires_stack
def test_compliance_mode_allows_raising_retention(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    admin = {"X-Abx-Admin-Key": "dev-admin-key"}
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "compliance_mode,retention_floor_days) VALUES (%s,180,TRUE,TRUE,180) "
            "ON CONFLICT (tenant_id) DO UPDATE SET retention_days=180,"
            "compliance_mode=TRUE,retention_floor_days=180",
            (tenant_id,),
        )
    response = client.put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "t", "retention_days": 400, "capture_payloads": True},
        headers=admin,
    )
    assert response.status_code == 200
    assert response.json()["retention_days"] == 400
