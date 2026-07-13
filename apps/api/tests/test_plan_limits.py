from __future__ import annotations

import uuid
from datetime import UTC, datetime

import psycopg
from abx_api.admin import set_plan
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client, get_payload
from conftest import requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}


def _event(seq: int, payload: str | None) -> dict[str, object]:
    return {
        "event_id": str(uuid.uuid4()),
        "agent_id": "plan-limit-agent",
        "session_id": f"plan-limit-{uuid.uuid4()}",
        "seq": seq,
        "ts": datetime.now(UTC).isoformat(),
        "source": "mcp_tap",
        "event_type": "agent_step",
        "operation": {"name": "plan_limit_test", "outcome": "success"},
        "resource_refs": [],
        "payload": payload,
    }


@requires_stack
def test_limit_degrades_payloads_without_rejecting_recording(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    client = TestClient(app)
    set_plan(tenant_id, "launch-preview", 1, 1)
    configured = client.get(
        "/v1/settings", params={"tenant_id": tenant_id}, headers=ADMIN
    )
    assert configured.status_code == 200, configured.text
    initial_usage = configured.json()["usage"]
    assert initial_usage["events"] == 0
    assert initial_usage["daily_event_plan_threshold"] == 1
    assert initial_usage["remaining_plan_events"] == 1
    assert initial_usage["plan_state"] == "within_plan"

    created = client.post(
        "/v1/settings/tokens",
        params={"tenant_id": tenant_id},
        headers=ADMIN,
        json={"kind": "recording", "label": "isolated recorder"},
    )
    assert created.status_code == 200, created.text
    isolated_token = created.json()["token"]

    response = client.post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": [_event(0, None), _event(1, "first payload")]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 2
    assert body["limit_state"] == "within_limit"
    assert body["over_limit_payload_events"] == 0
    assert body["payloads_omitted_by_limit"] == 0
    assert not {"usage_day", "daily_events", "daily_event_limit"} & body.keys()

    over_limit = client.post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": [_event(2, "over-limit payload")]},
    )
    assert over_limit.status_code == 200, over_limit.text
    assert over_limit.json()["accepted"] == 1
    assert over_limit.json()["over_limit_payload_events"] == 1
    assert over_limit.json()["payloads_omitted_by_limit"] == 1

    isolated = client.post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {isolated_token}"},
        json={"events": [_event(3, "isolated payload")]},
    )
    assert isolated.status_code == 200, isolated.text
    assert isolated.json()["limit_state"] == "within_limit"
    assert isolated.json()["payloads_omitted_by_limit"] == 0

    rows = ch_client().query(
        "SELECT payload_ref FROM events WHERE tenant_id=%(tenant)s "
        "AND agent_id='plan-limit-agent' ORDER BY chain_seq",
        parameters={"tenant": tenant_id},
    ).result_rows
    assert len(rows) == 4
    assert str(rows[0][0]) == ""
    assert get_payload(str(rows[1][0])) == b"first payload"
    assert str(rows[2][0]) == ""
    assert get_payload(str(rows[3][0])) == b"isolated payload"

    with psycopg.connect(settings.pg_dsn) as conn:
        usage = conn.execute(
            "SELECT events FROM metering_daily WHERE tenant_id=%s AND day=CURRENT_DATE",
            (tenant_id,),
        ).fetchone()
        token_usage = conn.execute(
            "SELECT captured_payload_events FROM metering_token_daily "
            "WHERE tenant_id=%s AND day=CURRENT_DATE ORDER BY token_id",
            (tenant_id,),
        ).fetchall()
    assert usage == (4,)
    assert token_usage == [(1,), (1,)]

    workspace = client.get(
        "/v1/settings", params={"tenant_id": tenant_id}, headers=ADMIN
    )
    assert workspace.status_code == 200, workspace.text
    workspace_body = workspace.json()
    assert workspace_body["plan_key"] == "launch-preview"
    assert workspace_body["usage"]["events"] == 4
    assert workspace_body["usage"]["remaining_plan_events"] == 0
    assert workspace_body["usage"]["plan_state"] == "over_plan"
    recording_tokens = [
        item for item in workspace_body["tokens"] if item["kind"] == "recording"
    ]
    assert [item["captured_payload_events_today"] for item in recording_tokens] == [1, 1]
    assert all(item["daily_payload_limit"] == 1 for item in recording_tokens)
    assert all(item["payload_allowance_state"] == "exhausted" for item in recording_tokens)
