import psycopg
from abx_api.auth import new_scan_token
from abx_api.main import app
from abx_api.settings import settings
from conftest import requires_stack
from fastapi.testclient import TestClient


@requires_stack
def test_local_scan_uses_write_only_token_and_persists_sanitized_findings(tenant) -> None:
    tenant_id, token = tenant
    scan_token, scan_hash = new_scan_token()
    with psycopg.connect(settings.pg_dsn) as conn:
        conn.execute(
            "INSERT INTO scan_upload_tokens (tenant_id, token_hash, label) VALUES (%s,%s,'test')",
            (tenant_id, scan_hash),
        )
    body = {
        "scope": "123456789012",
        "api_calls": 9,
        "findings": [
            {
                "natural_key": "aws:overpriv:AKIA-LOCAL",
                "finding_type": "over_privileged",
                "severity": "critical",
                "fingerprint": "AKIA-LOCAL",
                "owner": "arn:aws:iam::123456789012:user/local-bot",
                "evidence": {
                    "reach_count": 1,
                "reachable_resources": ["aws:*:*"],
                "destructive_actions": ["*"],
                "grants": [{
                    "action": "*", "resource": "aws:*:*", "kind": "all",
                    "environment": "unknown", "access": "admin",
                }],
                },
                "remediation": "Replace wildcard administration with least privilege.",
            }
        ],
    }
    client = TestClient(app)
    response = client.post(
        "/v1/scans/local",
        json=body,
        headers={"Authorization": f"Bearer {scan_token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["findings"] == 1

    dashboard = client.get(
        "/v1/dashboard/findings",
        params={"tenant_id": tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert dashboard.status_code == 200
    assert any(item["fingerprint"] == "AKIA-LOCAL" for item in dashboard.json())
    credentials = client.get(
        "/v1/dashboard/credentials", params={"tenant_id": tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    ).json()
    credential = client.get(
        f"/v1/dashboard/credentials/{credentials[0]['id']}",
        params={"tenant_id": tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert credential.status_code == 200
    assert credential.json()["permissions"][0]["resource"] == "aws:*:*"

    denied = client.get(
        "/v1/dashboard/findings",
        params={"tenant_id": tenant_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert denied.status_code == 401

    ingest_token_denied = client.post(
        "/v1/scans/local",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ingest_token_denied.status_code == 401

    too_large = client.post(
        "/v1/scans/local",
        content=b"x" * (settings.scan_upload_max_bytes + 1),
        headers={"Authorization": f"Bearer {scan_token}"},
    )
    assert too_large.status_code == 413
