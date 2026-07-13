from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from abx_api.anchor import anchor_all
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import s3_client
from botocore.exceptions import ClientError
from conftest import requires_stack
from fastapi.testclient import TestClient


@requires_stack
def test_anchor_version_has_compliance_retention_and_cannot_be_deleted(tenant) -> None:
    tenant_id, token = tenant
    event = {
        "event_id": str(uuid.uuid4()),
        "agent_id": "anchor-test-agent",
        "session_id": f"anchor-{uuid.uuid4()}",
        "seq": 0,
        "ts": datetime.now(UTC).isoformat(),
        "source": "mcp_tap",
        "event_type": "file_op",
        "operation": {
            "name": "read_anchor_marker",
            "provider": "filesystem",
            "target": "/anchor/marker",
            "outcome": "success",
            "duration_ms": 1,
        },
        "credential_ref": None,
        "resource_refs": ["file:/anchor/marker"],
        "payload": None,
    }
    response = TestClient(app).post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}"},
        json={"events": [event]},
    )
    assert response.status_code == 200, response.text
    before = datetime.now(UTC)
    assert anchor_all() >= 1

    key = f"{tenant_id}/{before:%Y-%m-%d}.json"
    versions = s3_client().list_object_versions(
        Bucket=settings.anchor_bucket, Prefix=key
    )["Versions"]
    latest = next(version for version in versions if version["Key"] == key and version["IsLatest"])
    version_id = latest["VersionId"]
    retention = s3_client().get_object_retention(
        Bucket=settings.anchor_bucket, Key=key, VersionId=version_id
    )["Retention"]
    assert retention["Mode"] == "COMPLIANCE"
    assert retention["RetainUntilDate"] > before + timedelta(
        days=settings.anchor_retention_days - 1
    )
    with pytest.raises(ClientError) as denied:
        s3_client().delete_object(
            Bucket=settings.anchor_bucket, Key=key, VersionId=version_id
        )
    assert denied.value.response["Error"]["Code"] in {"AccessDenied", "InvalidRequest"}
