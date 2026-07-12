from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from abx_api.main import app
from abx_api.retention import run_retention
from abx_api.store import ch_client, get_payload
from conftest import requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}


def _event(session_id: str, payload: str) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "agent_id": "settings-agent",
        "session_id": session_id,
        "seq": 0,
        "ts": datetime.now(UTC).isoformat(),
        "source": "mcp_tap",
        "event_type": "agent_step",
        "operation": {"name": "settings_test", "outcome": "success"},
        "resource_refs": [],
        "payload": payload,
    }


@requires_stack
def test_settings_manage_scoped_tokens_capture_and_retention(tenant) -> None:
    tenant_id, original_token = tenant
    client = TestClient(app)
    current = client.get("/v1/settings", params={"tenant_id": tenant_id}, headers=ADMIN)
    assert current.status_code == 200, current.text
    assert "aws-access-key-id" in current.json()["redaction_rules"]
    assert "github-token" in current.json()["redaction_rules"]
    assert "token_hash" not in current.text

    created = client.post(
        "/v1/settings/tokens", params={"tenant_id": tenant_id}, headers=ADMIN,
        json={"kind": "recording", "label": "rotation candidate"},
    )
    assert created.status_code == 200, created.text
    created_body = created.json()
    recording_token = created_body["token"]
    assert recording_token.startswith("abx_ingest_")

    captured = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {recording_token}"},
        json={"events": [_event("captured-before-disable", "payload to expire")]},
    )
    assert captured.status_code == 200, captured.text

    updated = client.put(
        "/v1/settings", params={"tenant_id": tenant_id}, headers=ADMIN,
        json={"tenant_name": "Settings Test", "retention_days": 1,
              "capture_payloads": False},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["capture_payloads"] is False
    assert updated.json()["tenant_name"] == "Settings Test"
    assert recording_token not in updated.text

    uncaptured = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {original_token}"},
        json={"events": [_event("capture-disabled", "must not enter object storage")]},
    )
    assert uncaptured.status_code == 200, uncaptured.text
    result = ch_client().query(
        "SELECT session_id,payload_ref FROM events WHERE tenant_id=%(tenant)s "
        "AND session_id IN ('captured-before-disable','capture-disabled')",
        parameters={"tenant": tenant_id},
    )
    refs = {str(row[0]): str(row[1]) for row in result.result_rows}
    assert refs["captured-before-disable"]
    assert refs["capture-disabled"] == ""
    assert get_payload(refs["captured-before-disable"]) is not None

    deleted = run_retention(datetime.now(UTC) + timedelta(days=2))
    assert deleted >= 1
    assert get_payload(refs["captured-before-disable"]) is None

    revoked = client.post(
        f"/v1/settings/tokens/recording/{created_body['id']}/revoke",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    )
    assert revoked.status_code == 200
    denied = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {recording_token}"},
        json={"events": [_event("after-revoke", "not accepted")]},
    )
    assert denied.status_code == 401
