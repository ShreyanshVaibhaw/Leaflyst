"""Phase 8 cold-path check: bootstrap -> local scan -> tap event -> alert -> replay."""

from __future__ import annotations

import json
import uuid

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from abx_tap.observer import Observer
from abx_tap.pump import CLIENT_TO_SERVER, ObservedLine
from fastapi.testclient import TestClient

HEADERS = {"X-ABX-Admin-Key": settings.admin_key}


def main() -> int:
    client = TestClient(app)
    user_ref = f"cold-smoke-{uuid.uuid4()}"
    bootstrap = client.post(
        "/v1/onboarding/bootstrap",
        headers=HEADERS,
        json={"user_ref": user_ref, "tenant_name": "Cold Path Smoke"},
    )
    bootstrap.raise_for_status()
    tenant_id = bootstrap.json()["tenant_id"]
    token = bootstrap.json()["ingest_token"]
    scan_token = bootstrap.json()["scan_token"]
    assert token and scan_token
    try:
        scan = client.post(
            "/v1/scans/local",
            headers={"Authorization": f"Bearer {scan_token}"},
            json={
                "scope": "customer-local-demo",
                "api_calls": 7,
                "findings": [
                    {
                        "natural_key": "aws:overpriv:AKIA-COLD-SMOKE",
                        "finding_type": "over_privileged",
                        "severity": "critical",
                        "fingerprint": "AKIA-COLD-SMOKE",
                        "owner": "arn:aws:iam::000000000000:user/cold-smoke",
                        "evidence": {"reach_count": 1, "reachable_resources": ["aws:*:*"]},
                        "remediation": "Replace wildcard access with a task-scoped role.",
                    }
                ],
            },
        )
        scan.raise_for_status()
        overview = client.get(
            "/v1/dashboard/overview",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
        )
        overview.raise_for_status()
        assert overview.json()["open_findings"] == 1
        assert overview.json()["scary_number"] == "1 open findings across your agent credentials"

        observer = Observer(agent_id="cold-path-agent", server_name="sandbox-db")
        wire = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "drop_database", "arguments": {"database": "sandbox"}},
            }
        ).encode()
        events = observer.observe(ObservedLine(CLIENT_TO_SERVER, wire))
        assert events and events[0]["source"] == "mcp_tap"
        ingest = client.post(
            "/v1/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": events},
        )
        ingest.raise_for_status()
        evaluated = client.post(
            "/v1/alerts/evaluate",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
        )
        evaluated.raise_for_status()
        assert evaluated.json()["alerts"] >= 1
        alerts = client.get(
            "/v1/alerts",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
        )
        alerts.raise_for_status()
        assert any(item["rule_id"] == "destructive_operation" for item in alerts.json())
        replay = client.get(
            f"/v1/replay/sessions/{observer.session_id}",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
        )
        replay.raise_for_status()
        assert replay.json()["verification"]["valid"] is True
        print("OK: cold self-serve bootstrap, scan, scary number, tap, session, and alert")
        return 0
    finally:
        _cleanup(tenant_id)


def _cleanup(tenant_id: str) -> None:
    with psycopg.connect(settings.pg_dsn) as conn:
        demo = conn.execute(
            "DELETE FROM demo_tenants WHERE owner_tenant_id=%s RETURNING demo_tenant_id",
            (tenant_id,),
        ).fetchone()
        if demo is not None:
            _delete_data(conn, str(demo[0]))
            conn.execute("DELETE FROM tenants WHERE id=%s", (demo[0],))
        _delete_data(conn, tenant_id)
        conn.execute("DELETE FROM tenants WHERE id=%s", (tenant_id,))


def _delete_data(conn, tenant_id: str) -> None:
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
        "tenant_members",
        "tenant_settings",
    ):
        conn.execute(f"DELETE FROM {table} WHERE tenant_id=%s", (tenant_id,))  # noqa: S608


if __name__ == "__main__":
    raise SystemExit(main())
