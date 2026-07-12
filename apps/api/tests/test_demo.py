from __future__ import annotations

from types import SimpleNamespace

from abx_api.main import app
from conftest import requires_stack
from fastapi.testclient import TestClient


@requires_stack
def test_pocketos_demo_runs_unattended_and_is_sandboxed(tenant, monkeypatch) -> None:
    tenant_id, _ = tenant
    monkeypatch.setattr("abx_api.demo.settings", SimpleNamespace(demo_enabled=True))
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
