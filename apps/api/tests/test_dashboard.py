"""Dashboard read API: tenant-scoped, admin-gated, renders scan findings."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from abx_api.main import app
from abx_api.settings import settings
from conftest import requires_stack
from fastapi.testclient import TestClient

pytestmark = requires_stack

client = TestClient(app)
ADMIN = {"X-Abx-Admin-Key": settings.admin_key}


@pytest.fixture
def seeded_tenant():
    """A tenant with one AWS credential and a couple of findings."""
    with psycopg.connect(settings.pg_dsn) as conn:
        tid = str(conn.execute(
            "INSERT INTO tenants (name) VALUES ('dash-test') RETURNING id"
        ).fetchone()[0])
        pid = str(conn.execute(
            "INSERT INTO principals (tenant_id, provider, kind, external_id) "
            "VALUES (%s, 'aws', 'iam_user', 'arn:aws:iam::1:user/svc-bot') RETURNING id",
            (tid,),
        ).fetchone()[0])
        cid = str(conn.execute(
            "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, owner_principal) "
            "VALUES (%s, 'aws', 'access_key', 'AKIATEST', %s) RETURNING id",
            (tid, pid),
        ).fetchone()[0])
        permission_id = str(conn.execute(
            "INSERT INTO permissions (tenant_id, principal_id, provider, scope) "
            "VALUES (%s, %s, 'aws', 's3:*') RETURNING id", (tid, pid)
        ).fetchone()[0])
        resource_id = str(conn.execute(
            "INSERT INTO resources (tenant_id, provider, kind, identifier) "
            "VALUES (%s, 'aws', 's3_bucket', 'aws:s3:prod-data') RETURNING id", (tid,)
        ).fetchone()[0])
        conn.execute(
            "INSERT INTO permission_reaches_resource (permission_id, resource_id, access) "
            "VALUES (%s, %s, 'admin')", (permission_id, resource_id)
        )
        conn.execute(
            "INSERT INTO scan_runs (tenant_id, provider, status, finished_at) "
            "VALUES (%s, 'aws', 'succeeded', now())", (tid,)
        )
        for ftype, sev, key in [
            ("over_privileged", "critical", "aws:overpriv:AKIATEST"),
            ("orphaned_credential", "high", "aws:orphaned:AKIATEST"),
        ]:
            conn.execute(
                "INSERT INTO findings (tenant_id, finding_type, natural_key, severity, "
                "credential_id, evidence, remediation) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (tid, ftype, key, sev, cid,
                 psycopg.types.json.Jsonb({"fingerprint": "AKIATEST",
                                           "principal": "svc-bot"}),
                 "fix it"),
            )
        conn.commit()
    yield tid
    with psycopg.connect(settings.pg_dsn) as conn:
        conn.execute(
            "DELETE FROM permission_reaches_resource WHERE permission_id IN "
            "(SELECT id FROM permissions WHERE tenant_id = %s)", (tid,)
        )
        conn.execute("DELETE FROM findings WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM permissions WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM resources WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM integration_connections WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM credentials WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM principals WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM scan_runs WHERE tenant_id = %s", (tid,))
        conn.execute("DELETE FROM tenants WHERE id = %s", (tid,))
        conn.commit()


def test_overview_scary_number(seeded_tenant: str) -> None:
    resp = client.get("/v1/dashboard/overview",
                      params={"tenant_id": seeded_tenant}, headers=ADMIN)
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings_by_severity"]["critical"] == 1
    assert body["open_findings"] == 2
    assert body["credentials"] == 1
    assert "aws" in body["providers_scanned"]
    assert body["scary_number"] == "1 credential belongs to a dead or dormant agent"


def test_findings_list_sorted_by_severity(seeded_tenant: str) -> None:
    resp = client.get("/v1/dashboard/findings",
                      params={"tenant_id": seeded_tenant}, headers=ADMIN)
    findings = resp.json()
    assert [f["severity"] for f in findings] == ["critical", "high"]
    assert findings[0]["remediation"] == "fix it"
    assert findings[0]["provider"] == "aws"

    github = client.get(
        "/v1/dashboard/findings",
        params={"tenant_id": seeded_tenant, "provider": "github"},
        headers=ADMIN,
    )
    assert github.json() == []


def test_credentials_inventory(seeded_tenant: str) -> None:
    resp = client.get("/v1/dashboard/credentials",
                      params={"tenant_id": seeded_tenant}, headers=ADMIN)
    creds = resp.json()
    assert len(creds) == 1
    assert creds[0]["fingerprint"] == "AKIATEST"
    assert creds[0]["open_findings"] == 2

    detail = client.get(
        f"/v1/dashboard/credentials/{creds[0]['id']}",
        params={"tenant_id": seeded_tenant},
        headers=ADMIN,
    )
    assert detail.status_code == 200
    assert detail.json()["permissions"][0] == {
        "scope": "s3:*", "resource": "aws:s3:prod-data", "access": "admin"
    }
    assert len(detail.json()["findings"]) == 2


def test_exports(seeded_tenant: str) -> None:
    csv_resp = client.get("/v1/dashboard/findings.csv",
                          params={"tenant_id": seeded_tenant}, headers=ADMIN)
    assert "AKIATEST" in csv_resp.text
    md_resp = client.get("/v1/dashboard/findings.md",
                         params={"tenant_id": seeded_tenant}, headers=ADMIN)
    assert "CRITICAL" in md_resp.text


def test_admin_key_required() -> None:
    resp = client.get("/v1/dashboard/overview", params={"tenant_id": str(uuid.uuid4())})
    assert resp.status_code == 401


def test_tenant_isolation(seeded_tenant: str) -> None:
    # A different tenant id sees nothing of the seeded tenant.
    other = str(uuid.uuid4())
    resp = client.get("/v1/dashboard/findings",
                      params={"tenant_id": other}, headers=ADMIN)
    assert resp.json() == []
