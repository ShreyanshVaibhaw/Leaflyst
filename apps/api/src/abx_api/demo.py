"""Deterministic, sandbox-only PocketOS reenactment for the product demo."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from abx_api.alerts import evaluate_event_ids
from abx_api.auth import require_admin
from abx_api.ingest import IngestBatch, ingest
from abx_api.settings import settings
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/demo", dependencies=[Depends(require_admin)])

FINGERPRINT = "AKIA-DEMO-POCKETOS"
AGENT = "pocketos-sandbox"
RESOURCE = "aws:rds:prod-orders"


class DemoResult(BaseModel):
    tenant_id: str
    session_id: str
    agent_id: str
    credential_id: str
    finding_id: str
    alert_ids: list[str]
    scanner_warning: str
    destructive_attempt: str
    sandboxed: bool = True


def _demo_tenant(owner_tenant_id: str) -> str:
    with pg_pool().connection() as conn:
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s))",
            (f"{owner_tenant_id}:demo-tenant",),
        )
        existing = conn.execute(
            "SELECT demo_tenant_id FROM demo_tenants WHERE owner_tenant_id=%s",
            (owner_tenant_id,),
        ).fetchone()
        if existing is not None:
            return str(existing[0])
        tenant = conn.execute(
            "INSERT INTO tenants (name) VALUES ('PocketOS isolated demo') RETURNING id"
        ).fetchone()
        assert tenant is not None
        conn.execute(
            "INSERT INTO demo_tenants (owner_tenant_id, demo_tenant_id) VALUES (%s,%s)",
            (owner_tenant_id, tenant[0]),
        )
        return str(tenant[0])


def _seed_graph(tenant_id: str) -> tuple[str, str]:
    with pg_pool().connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{tenant_id}:pocketos-demo",))
        principal = conn.execute(
            "INSERT INTO principals (tenant_id, provider, kind, external_id, human_owner) "
            "VALUES (%s, 'aws', 'iam_user', 'arn:aws:iam::000000000000:user/pocketos-demo', "
            "'PocketOS demo') ON CONFLICT (tenant_id, provider, external_id) DO UPDATE "
            "SET human_owner=EXCLUDED.human_owner RETURNING id",
            (tenant_id,),
        ).fetchone()
        assert principal is not None
        credential = conn.execute(
            "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, "
            "owner_principal, created_at_provider) VALUES (%s, 'aws', 'access_key', %s, %s, "
            "now() - interval '180 days') ON CONFLICT (tenant_id, provider, fingerprint) "
            "DO UPDATE SET last_scanned=now() RETURNING id",
            (tenant_id, FINGERPRINT, principal[0]),
        ).fetchone()
        assert credential is not None
        agent = conn.execute(
            "INSERT INTO agents (tenant_id, name, framework, environment, first_seen) "
            "VALUES (%s, %s, 'mcp', 'dev', now() - interval '30 days') "
            "ON CONFLICT (tenant_id, name) DO UPDATE SET framework=EXCLUDED.framework "
            "RETURNING id",
            (tenant_id, AGENT),
        ).fetchone()
        assert agent is not None
        conn.execute(
            "INSERT INTO agent_holds_credential (agent_id, credential_id, inferred_from) "
            "VALUES (%s, %s, 'traffic') ON CONFLICT DO NOTHING",
            (agent[0], credential[0]),
        )
        permission = conn.execute(
            "SELECT id FROM permissions WHERE tenant_id=%s AND credential_id=%s "
            "AND scope='AdministratorAccess' LIMIT 1",
            (tenant_id, credential[0]),
        ).fetchone()
        if permission is None:
            permission = conn.execute(
                "INSERT INTO permissions (tenant_id, credential_id, provider, scope, raw) "
                "VALUES (%s, %s, 'aws', 'AdministratorAccess', %s) RETURNING id",
                (tenant_id, credential[0], Jsonb({"demo": True, "secret_values": False})),
            ).fetchone()
        assert permission is not None
        resource = conn.execute(
            "INSERT INTO resources (tenant_id, provider, kind, identifier, environment) "
            "VALUES (%s, 'aws', 'rds_database', %s, 'prod') "
            "ON CONFLICT (tenant_id, provider, identifier) DO UPDATE "
            "SET environment=EXCLUDED.environment RETURNING id",
            (tenant_id, RESOURCE),
        ).fetchone()
        assert resource is not None
        conn.execute(
            "INSERT INTO permission_reaches_resource (permission_id, resource_id, access) "
            "VALUES (%s, %s, 'admin') ON CONFLICT DO NOTHING",
            (permission[0], resource[0]),
        )
        finding = conn.execute(
            "INSERT INTO findings (tenant_id, finding_type, natural_key, severity, "
            "credential_id, evidence, remediation) VALUES "
            "(%s, 'over_privileged', 'demo:pocketos:over-scoped', 'critical', %s, %s, "
            "'Replace AdministratorAccess with a task-scoped role') "
            "ON CONFLICT (tenant_id, natural_key) DO UPDATE SET last_seen=now(), status='open' "
            "RETURNING id",
            (tenant_id, credential[0], Jsonb({"scope": "AdministratorAccess"})),
        ).fetchone()
        assert finding is not None
        scanned = conn.execute(
            "SELECT 1 FROM scan_runs WHERE tenant_id=%s AND provider='aws' "
            "AND scope='pocketos-demo/read-only' LIMIT 1",
            (tenant_id,),
        ).fetchone()
        if scanned is None:
            conn.execute(
                "INSERT INTO scan_runs (tenant_id, provider, scope, finished_at, api_calls, "
                "status) VALUES (%s, 'aws', 'pocketos-demo/read-only', now(), 7, 'succeeded')",
                (tenant_id,),
            )
    return str(credential[0]), str(finding[0])


@router.post("/run", response_model=DemoResult)
def run_demo(tenant_id: str) -> DemoResult:
    if not settings.demo_enabled:
        raise HTTPException(status_code=404, detail="demo is disabled")
    demo_tenant_id = _demo_tenant(tenant_id)
    credential_id, finding_id = _seed_graph(demo_tenant_id)
    session_id = f"pocketos-{uuid.uuid4().hex[:12]}"
    event_id = uuid.uuid4()
    event = IngestEvent.model_validate(
        {
            "event_id": str(event_id),
            "agent_id": AGENT,
            "session_id": session_id,
            "seq": 1,
            "ts": datetime.now(UTC).isoformat(),
            "source": "mcp_tap",
            "event_type": "db_op",
            "operation": {
                "name": "drop_database",
                "provider": "aws",
                "target": RESOURCE,
                "outcome": "denied",
                "duration_ms": 12,
            },
            "credential_ref": FINGERPRINT,
            "resource_refs": [RESOURCE],
            "payload": "Sandbox intercepted DROP DATABASE prod_orders; no command was executed.",
        }
    )
    ingest(IngestBatch(events=[event]), demo_tenant_id)
    evaluate_event_ids(demo_tenant_id, [str(event_id)])
    with pg_pool().connection() as conn:
        alerts = conn.execute(
            "SELECT id FROM alerts WHERE tenant_id=%s AND session_id=%s ORDER BY first_seen",
            (demo_tenant_id, session_id),
        ).fetchall()
    return DemoResult(
        tenant_id=demo_tenant_id,
        session_id=session_id,
        agent_id=AGENT,
        credential_id=credential_id,
        finding_id=finding_id,
        alert_ids=[str(row[0]) for row in alerts],
        scanner_warning="AdministratorAccess reaches a production database",
        destructive_attempt="DROP DATABASE prod_orders was intercepted and denied",
    )
