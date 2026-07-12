"""Incident report assembly, integrity evidence, and untrusted-text escaping."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import s3_client
from conftest import requires_stack
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

pytestmark = requires_stack
client = TestClient(app)
ADMIN = {"X-Abx-Admin-Key": settings.admin_key}


def test_report_contains_forensic_sections_and_escapes_markup(
    tenant: tuple[str, str],
) -> None:
    tenant_id, token = tenant
    fingerprint = "AKIA1234567890ABCDEF"
    with psycopg.connect(settings.pg_dsn) as conn:
        principal = conn.execute(
            "INSERT INTO principals (tenant_id,provider,kind,external_id) "
            "VALUES (%s,'aws','iam_user','arn:aws:iam::1:user/report-bot') RETURNING id",
            (tenant_id,),
        ).fetchone()[0]
        credential = conn.execute(
            "INSERT INTO credentials (tenant_id,provider,kind,fingerprint,owner_principal) "
            "VALUES (%s,'aws','access_key',%s,%s) RETURNING id",
            (tenant_id, fingerprint, principal),
        ).fetchone()[0]
        permission = conn.execute(
            "INSERT INTO permissions (tenant_id,credential_id,provider,scope) "
            "VALUES (%s,%s,'aws','rds:*') RETURNING id",
            (tenant_id, credential),
        ).fetchone()[0]
        resource = conn.execute(
            "INSERT INTO resources (tenant_id,provider,kind,identifier,environment) "
            "VALUES (%s,'aws','database','aws:rds:prod','prod') RETURNING id",
            (tenant_id,),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO permission_reaches_resource (permission_id,resource_id,access) "
            "VALUES (%s,%s,'admin')",
            (permission, resource),
        )
    event_id = str(uuid.uuid4())
    session_id = "report-session"
    response = client.post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "events": [
                {
                    "event_id": event_id,
                    "agent_id": "report-bot",
                    "session_id": session_id,
                    "seq": 0,
                    "ts": datetime.now(UTC).isoformat(),
                    "source": "mcp_tap",
                    "event_type": "db_op",
                    "operation": {
                        "name": "drop <script>alert(1)</script> [open](javascript:alert(2))",
                        "provider": "aws",
                        "target": "prod|customers",
                        "outcome": "success",
                        "duration_ms": 9,
                    },
                    "credential_ref": fingerprint,
                    "resource_refs": ["aws:rds:prod"],
                    "payload": "untrusted payload",
                }
            ]
        },
    )
    assert response.status_code == 200, response.text
    with psycopg.connect(settings.pg_dsn) as conn:
        conn.execute(
            "INSERT INTO alerts (tenant_id,rule_id,dedupe_key,severity,title,agent_id,"
            "credential_ref,event_id,session_id,evidence) VALUES "
            "(%s,'destructive_operation','report-alert','critical','Destructive operation',"
            "'report-bot',%s,%s,%s,%s)",
            (tenant_id, fingerprint, event_id, session_id, Jsonb({"operation": "drop"})),
        )
    with psycopg.connect(settings.pg_dsn) as conn:
        head = conn.execute(
            "SELECT head_hash,head_seq FROM chain_heads WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
        assert head is not None
    anchor_key = f"{tenant_id}/2026-07-12.json"
    s3_client().put_object(
        Bucket=settings.anchor_bucket,
        Key=anchor_key,
        Body=json.dumps(
            {
                "tenant_id": tenant_id,
                "head_hash": head[0],
                "head_seq": head[1],
                "anchored_at": datetime.now(UTC).isoformat(),
            }
        ).encode(),
    )

    report = client.get(
        f"/v1/reports/sessions/{session_id}",
        params={"tenant_id": tenant_id},
        headers=ADMIN,
    )
    assert report.status_code == 200, report.text
    body = report.json()
    assert body["verification"]["valid"] is True
    assert body["credentials"][0]["scopes"] == ["rds:*"]
    assert body["blast_radius"][0]["resource_ref"] == "aws:rds:prod"
    assert body["alerts"][0]["rule_id"] == "destructive_operation"
    assert body["anchor_ref"].endswith(anchor_key)
    assert body["anchor_status"] == "matched"
    markdown = body["markdown"]
    assert "## Executive summary" in markdown
    assert "## Technical appendix" in markdown
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown
    assert "\\[open\\]\\(javascript:alert\\(2\\)\\)" in markdown
    assert "prod\\|customers" in markdown

    downloaded = client.get(
        f"/v1/reports/sessions/{session_id}.md",
        params={"tenant_id": tenant_id},
        headers=ADMIN,
    )
    assert downloaded.status_code == 200
    assert "## Executive summary" in downloaded.text
    assert "&lt;script&gt;" in downloaded.text
