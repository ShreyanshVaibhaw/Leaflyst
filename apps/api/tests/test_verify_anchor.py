from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from abx_api.anchor import anchor_all
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client, s3_client
from conftest import requires_stack
from fastapi.testclient import TestClient

pytestmark = requires_stack
client = TestClient(app)
ADMIN = {"X-Abx-Admin-Key": settings.admin_key}


def _event(session_id: str, seq: int) -> dict[str, object]:
    return {
        "event_id": str(uuid.uuid4()),
        "agent_id": "verify-agent",
        "session_id": session_id,
        "seq": seq,
        "ts": datetime.now(UTC).isoformat(),
        "source": "mcp_tap",
        "event_type": "tool_call",
        "operation": {
            "name": f"read item {seq}",
            "provider": "filesystem",
            "target": f"/tmp/{seq}",
            "outcome": "success",
            "duration_ms": 1,
        },
        "credential_ref": None,
        "resource_refs": [f"file:/tmp/{seq}"],
        "payload": None,
    }


def _ingest(tenant_id: str, token: str, session_id: str, start: int, count: int) -> None:
    response = client.post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": [_event(session_id, start + offset) for offset in range(count)]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == count


def test_full_head_verification_uses_latest_anchor_suffix(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    session_id = f"verify-anchor-{uuid.uuid4()}"
    _ingest(tenant_id, token, session_id, 0, 3)
    assert anchor_all() >= 1
    _ingest(tenant_id, token, session_id, 3, 2)

    anchored = client.get(
        "/v1/chain/verify",
        params={"tenant_id": tenant_id},
        headers=ADMIN,
    )
    assert anchored.status_code == 200, anchored.text
    body = anchored.json()
    assert body["valid"] is True
    assert body["verification_mode"] == "anchored_suffix"
    assert body["anchor_head_seq"] == 3
    assert body["events_checked"] == 3
    assert body["anchor_ref"].startswith(f"s3://{settings.anchor_bucket}/{tenant_id}/")

    ranged = client.get(
        "/v1/chain/verify",
        params={"tenant_id": tenant_id, "from_chain_seq": 1, "to_chain_seq": 5},
        headers=ADMIN,
    )
    assert ranged.status_code == 200, ranged.text
    assert ranged.json()["verification_mode"] == "range"
    assert ranged.json()["events_checked"] == 5


def test_latest_anchor_mismatch_fails_closed(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    session_id = f"verify-anchor-mismatch-{uuid.uuid4()}"
    _ingest(tenant_id, token, session_id, 0, 3)
    assert anchor_all() >= 1
    s3_client().put_object(
        Bucket=settings.anchor_bucket,
        Key=f"{tenant_id}/2099-01-01.json",
        Body=json.dumps(
            {
                "tenant_id": tenant_id,
                "head_hash": "0" * 64,
                "head_seq": 3,
                "anchored_at": "2099-01-01T00:00:00.000+00:00",
            }
        ).encode(),
    )

    response = client.get(
        "/v1/chain/verify",
        params={"tenant_id": tenant_id},
        headers=ADMIN,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is False
    assert body["verification_mode"] == "anchor_failed"
    assert body["events_checked"] == 1


def test_suffix_tamper_fails_anchored_verification(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    session_id = f"verify-anchor-tamper-{uuid.uuid4()}"
    _ingest(tenant_id, token, session_id, 0, 3)
    assert anchor_all() >= 1
    _ingest(tenant_id, token, session_id, 3, 2)

    result = ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(tenant)s AND chain_seq=4 LIMIT 1",
        parameters={"tenant": tenant_id},
    )
    forged = list(result.result_rows[0])
    forged[0] = uuid.uuid4()
    forged[20] = b"0" * 64
    ch_client().insert("events", [forged], column_names=result.column_names)

    response = client.get(
        "/v1/chain/verify",
        params={"tenant_id": tenant_id},
        headers=ADMIN,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is False
    assert body["verification_mode"] == "anchored_suffix"
