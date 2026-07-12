from __future__ import annotations

import uuid
from types import SimpleNamespace

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from conftest import requires_stack
from fastapi.testclient import TestClient

HEADERS = {"X-ABX-Admin-Key": "dev-admin-key"}


def _new_tenant() -> str:
    with psycopg.connect(settings.pg_dsn) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"isolation-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        assert row is not None
        return str(row[0])


def _delete_tenant(tenant_id: str) -> None:
    with psycopg.connect(settings.pg_dsn) as conn:
        conn.execute(
            "DELETE FROM permission_reaches_resource WHERE permission_id IN "
            "(SELECT id FROM permissions WHERE tenant_id=%s)",
            (tenant_id,),
        )
        conn.execute(
            "DELETE FROM agent_holds_credential WHERE credential_id IN "
            "(SELECT id FROM credentials WHERE tenant_id=%s)",
            (tenant_id,),
        )
        for table in (
            "revocation_actions",
            "alerts",
            "alert_channels",
            "findings",
            "permissions",
            "resources",
            "integration_connections",
            "credentials",
            "principals",
            "agents",
            "scan_runs",
            "session_shares",
            "session_sequences",
            "metering_daily",
            "scan_upload_tokens",
            "ingest_tokens",
            "chain_heads",
            "tenant_settings",
        ):
            conn.execute(f"DELETE FROM {table} WHERE tenant_id=%s", (tenant_id,))  # noqa: S608
        conn.execute("DELETE FROM tenants WHERE id=%s", (tenant_id,))


@requires_stack
def test_tenant_cannot_read_or_mutate_another_tenant_by_any_api_path(
    tenant,
    monkeypatch,
) -> None:
    tenant_a, _ = tenant
    tenant_b = _new_tenant()
    monkeypatch.setattr("abx_api.demo.settings", SimpleNamespace(demo_enabled=True))
    client = TestClient(app)
    try:
        created = client.post(
            "/v1/demo/run",
            params={"tenant_id": tenant_a},
            headers=HEADERS,
        )
        assert created.status_code == 200, created.text
        ids = created.json()

        object_paths = [
            f"/v1/dashboard/findings/{ids['finding_id']}",
            f"/v1/dashboard/credentials/{ids['credential_id']}",
            f"/v1/replay/sessions/{ids['session_id']}",
            f"/v1/reports/sessions/{ids['session_id']}",
            f"/v1/revocation/{ids['credential_id']}/impact",
        ]
        for path in object_paths:
            response = client.get(path, params={"tenant_id": tenant_b}, headers=HEADERS)
            assert response.status_code == 404, (path, response.text)

        lists = [
            "/v1/dashboard/findings",
            "/v1/dashboard/credentials",
            "/v1/replay/agents",
            "/v1/alerts",
        ]
        for path in lists:
            response = client.get(path, params={"tenant_id": tenant_b}, headers=HEADERS)
            assert response.status_code == 200, (path, response.text)
            serialized = response.text
            assert ids["session_id"] not in serialized
            assert ids["credential_id"] not in serialized
            assert ids["finding_id"] not in serialized

        acknowledge = client.post(
            f"/v1/alerts/{ids['alert_ids'][0]}/acknowledge",
            params={"tenant_id": tenant_b},
            headers=HEADERS,
        )
        assert acknowledge.status_code == 404
        with psycopg.connect(settings.pg_dsn) as conn:
            token = conn.execute(
                "SELECT id FROM ingest_tokens WHERE tenant_id=%s LIMIT 1", (tenant_a,)
            ).fetchone()
            assert token is not None
        revoke = client.post(
            f"/v1/settings/tokens/recording/{token[0]}/revoke",
            params={"tenant_id": tenant_b},
            headers=HEADERS,
        )
        assert revoke.status_code == 404
    finally:
        _delete_tenant(tenant_b)
