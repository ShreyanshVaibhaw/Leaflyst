from __future__ import annotations

import hashlib
import uuid

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from conftest import requires_stack
from fastapi.testclient import TestClient


@requires_stack
def test_bootstrap_is_idempotent_and_token_is_shown_once() -> None:
    user_ref = f"user-{uuid.uuid4()}"
    client = TestClient(app)
    headers = {"X-ABX-Admin-Key": "dev-admin-key"}
    first = client.post(
        "/v1/onboarding/bootstrap",
        headers=headers,
        json={"user_ref": user_ref, "tenant_name": "Cold Start Co"},
    )
    assert first.status_code == 200, first.text
    created = first.json()
    assert created["created"] is True
    assert created["ingest_token"].startswith("abx_ingest_")
    assert created["scan_token"].startswith("abx_scan_")
    authorized = client.get(
        "/v1/onboarding/authorize", headers=headers,
        params={"user_ref": user_ref, "tenant_id": created["tenant_id"]},
    )
    assert authorized.status_code == 200
    assert authorized.json() == {"authorized": True}

    second = client.post(
        "/v1/onboarding/bootstrap",
        headers=headers,
        json={"user_ref": user_ref, "tenant_name": "Renamed by retry"},
    )
    assert second.status_code == 200
    assert second.json() == {
        "tenant_id": created["tenant_id"],
        "ingest_token": None,
        "scan_token": None,
        "created": False,
    }

    with psycopg.connect(settings.pg_dsn) as conn:
        stored = conn.execute(
            "SELECT token_hash FROM ingest_tokens WHERE tenant_id=%s",
            (created["tenant_id"],),
        ).fetchone()
        scan_stored = conn.execute(
            "SELECT token_hash FROM scan_upload_tokens WHERE tenant_id=%s",
            (created["tenant_id"],),
        ).fetchone()
        assert stored is not None
        assert scan_stored is not None
        assert stored[0] == hashlib.sha256(created["ingest_token"].encode()).hexdigest()
        assert scan_stored[0] == hashlib.sha256(created["scan_token"].encode()).hexdigest()
        assert created["ingest_token"] not in str(stored)
        assert created["scan_token"] not in str(scan_stored)
        conn.execute("DELETE FROM tenant_members WHERE tenant_id=%s", (created["tenant_id"],))
        conn.execute("DELETE FROM scan_upload_tokens WHERE tenant_id=%s", (created["tenant_id"],))
        conn.execute("DELETE FROM ingest_tokens WHERE tenant_id=%s", (created["tenant_id"],))
        conn.execute("DELETE FROM tenants WHERE id=%s", (created["tenant_id"],))
