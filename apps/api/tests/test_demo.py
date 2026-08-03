from __future__ import annotations

from dataclasses import replace

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient


@requires_stack
def test_pocketos_demo_runs_unattended_and_is_sandboxed(tenant, monkeypatch) -> None:
    tenant_id, _ = tenant
    monkeypatch.setattr("abx_api.demo.settings", replace(settings, demo_enabled=True))
    response = TestClient(app).post(
        "/v1/demo/run",
        params={"tenant_id": tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert response.status_code == 200, response.text
    result = response.json()
    demo_tenant_id = result["tenant_id"]
    assert demo_tenant_id != tenant_id
    assert result["sandboxed"] is True
    assert result["session_id"].startswith("pocketos-")
    assert result["alert_ids"]
    assert "production database" in result["scanner_warning"]
    assert "intercepted and denied" in result["destructive_attempt"]

    replay = TestClient(app).get(
        f"/v1/replay/sessions/{result['session_id']}",
        params={"tenant_id": demo_tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert replay.status_code == 200, replay.text
    body = replay.json()
    assert body["verification"]["valid"] is True
    assert any(item.get("operation") == "drop_database" for item in body["timeline"])
    assert any(item["resource_ref"] == "aws:rds:prod-orders" for item in body["blast_radius"])

    impact = TestClient(app).get(
        f"/v1/revocation/{result['credential_id']}/impact",
        params={"tenant_id": demo_tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert impact.status_code == 200, impact.text
    assert impact.json()["guided_commands"]


@requires_stack
def test_public_demo_is_per_visitor_rate_limited_and_read_only(monkeypatch) -> None:
    visitor_a = "a" * 64
    visitor_b = "b" * 64
    # replace() rather than a SimpleNamespace: a stand-in that only carries the
    # fields this test happens to read silently stops exercising every limit
    # added afterwards, which is how an unbounded path hides behind a green test.
    monkeypatch.setattr(
        "abx_api.demo.settings",
        replace(
            settings,
            demo_enabled=True,
            public_demo_max_runs_per_hour=2,
            public_demo_ttl_hours=1,
        ),
    )
    client = TestClient(app)
    tenant_ids: set[str] = set()
    try:
        first = client.post(
            "/v1/demo/public/run",
            json={"visitor_ref": visitor_a},
            headers={"X-ABX-Admin-Key": "dev-admin-key"},
        )
        assert first.status_code == 200, first.text
        first_result = first.json()
        tenant_ids.add(first_result["tenant_id"])
        assert first_result["sandboxed"] is True
        assert first_result["share_path"].startswith("/share/abx_share_")

        replay_path = first_result["share_path"].replace("/share/", "/v1/replay/shared/")
        replay = client.get(replay_path)
        assert replay.status_code == 200, replay.text
        assert replay.json()["read_only"] is True

        second = client.post(
            "/v1/demo/public/run",
            json={"visitor_ref": visitor_a},
            headers={"X-ABX-Admin-Key": "dev-admin-key"},
        )
        assert second.status_code == 200, second.text
        assert second.json()["tenant_id"] == first_result["tenant_id"]

        limited = client.post(
            "/v1/demo/public/run",
            json={"visitor_ref": visitor_a},
            headers={"X-ABX-Admin-Key": "dev-admin-key"},
        )
        assert limited.status_code == 429

        isolated = client.post(
            "/v1/demo/public/run",
            json={"visitor_ref": visitor_b},
            headers={"X-ABX-Admin-Key": "dev-admin-key"},
        )
        assert isolated.status_code == 200, isolated.text
        tenant_ids.add(isolated.json()["tenant_id"])
        assert isolated.json()["tenant_id"] != first_result["tenant_id"]

        invalid = client.post(
            "/v1/demo/public/run",
            json={"visitor_ref": "not-a-hash"},
            headers={"X-ABX-Admin-Key": "dev-admin-key"},
        )
        assert invalid.status_code == 422

        tenant_a, tenant_b = tenant_ids
        with psycopg.connect(settings.pg_dsn) as conn:
            members = conn.execute(
                "SELECT count(*) FROM tenant_members WHERE tenant_id IN (%s,%s)",
                (tenant_a, tenant_b),
            ).fetchone()
        assert members is not None and members[0] == 0
    finally:
        with psycopg.connect(settings.pg_dsn) as conn:
            rows = conn.execute(
                "DELETE FROM public_demo_tenants WHERE visitor_ref IN (%s,%s) "
                "RETURNING demo_tenant_id",
                (visitor_a, visitor_b),
            ).fetchall()
            for row in rows:
                _delete_tenant_data(conn, str(row[0]))
                conn.execute("DELETE FROM tenants WHERE id=%s", (row[0],))
            conn.commit()
