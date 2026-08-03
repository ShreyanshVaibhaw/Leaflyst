"""Deterministic, sandbox-only PocketOS reenactment for the product demo."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from abx_api.alerts import evaluate_event_ids
from abx_api.ingest import ingest_events
from abx_api.rbac import require_configure
from abx_api.replay import ShareRequest, create_share
from abx_api.settings import settings
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/demo", dependencies=[Depends(require_configure)])

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


class PublicDemoRequest(BaseModel):
    visitor_ref: str = Field(pattern=r"^[0-9a-f]{64}$")


class PublicDemoResult(DemoResult):
    share_path: str
    expires_at: str


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


# Tables the public demo writes into, in an order that respects their foreign
# keys. Reclaiming an expired sandbox has to remove the rows, not just the
# bookkeeping row that points at them.
_DEMO_TENANT_TABLES = (
    "DELETE FROM permission_reaches_resource WHERE permission_id IN "
    "(SELECT id FROM permissions WHERE tenant_id = ANY(%(ids)s))",
    "DELETE FROM agent_holds_credential WHERE credential_id IN "
    "(SELECT id FROM credentials WHERE tenant_id = ANY(%(ids)s))",
    "DELETE FROM alerts WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM session_shares WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM session_sequences WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM chain_heads WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM metering_token_daily WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM metering_daily WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM findings WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM scan_runs WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM permissions WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM resources WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM credentials WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM agents WHERE tenant_id = ANY(%(ids)s)",
    "DELETE FROM principals WHERE tenant_id = ANY(%(ids)s)",
)


def purge_expired_public_demos(now: datetime | None = None) -> int:
    """Reclaim sandboxes past their TTL. Returns how many were reclaimed.

    Without this the live-sandbox cap below would eventually be a permanent
    closed sign rather than a limit: every slot taken, none ever returned.
    """
    current = (now or datetime.now(UTC)).astimezone(UTC)
    with pg_pool().connection() as conn:
        expired = conn.execute(
            "SELECT demo_tenant_id FROM public_demo_tenants WHERE expires_at <= %s "
            "FOR UPDATE SKIP LOCKED",
            (current,),
        ).fetchall()
        if not expired:
            return 0
        ids = [row[0] for row in expired]
        for statement in _DEMO_TENANT_TABLES:
            conn.execute(statement, {"ids": ids})
        conn.execute("DELETE FROM public_demo_tenants WHERE demo_tenant_id = ANY(%s)", (ids,))
    return len(ids)


def _public_demo_budget(conn: object, now: datetime, creating: bool) -> None:
    """Enforce the limits that a rotated visitor cookie cannot step around.

    The per-visitor limit is keyed on a value the visitor supplies, so on its own
    it only restrains a visitor who keeps the same cookie. These two do not care
    who is asking.
    """
    live, runs = conn.execute(  # type: ignore[attr-defined]
        "SELECT count(*), COALESCE(sum(runs_in_window) FILTER "
        "(WHERE window_started_at > %(now)s - interval '1 hour'), 0) "
        "FROM public_demo_tenants",
        {"now": now},
    ).fetchone()
    if int(runs) >= settings.public_demo_max_runs_per_hour_global:
        raise HTTPException(status_code=429, detail="public demo is at its hourly budget")
    if creating and int(live) >= settings.public_demo_max_live_tenants:
        raise HTTPException(status_code=429, detail="public demo has no free sandbox")


def _public_demo_tenant(visitor_ref: str) -> str:
    now = datetime.now(UTC)
    purge_expired_public_demos(now)
    with pg_pool().connection() as conn:
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s))",
            (f"public-demo:{visitor_ref}",),
        )
        existing = conn.execute(
            "SELECT demo_tenant_id,window_started_at,runs_in_window "
            "FROM public_demo_tenants WHERE visitor_ref=%s",
            (visitor_ref,),
        ).fetchone()
        _public_demo_budget(conn, now, creating=existing is None)
        if existing is None:
            tenant = conn.execute(
                "INSERT INTO tenants (name) VALUES ('PocketOS public sandbox') RETURNING id"
            ).fetchone()
            assert tenant is not None
            conn.execute(
                "INSERT INTO public_demo_tenants "
                "(visitor_ref,demo_tenant_id,runs_in_window,last_run_at,expires_at) "
                "VALUES (%s,%s,1,%s,%s)",
                (
                    visitor_ref,
                    tenant[0],
                    now,
                    now + timedelta(hours=settings.public_demo_ttl_hours),
                ),
            )
            return str(tenant[0])

        window_started_at = existing[1]
        runs_in_window = int(existing[2])
        if window_started_at <= now - timedelta(hours=1):
            window_started_at = now
            runs_in_window = 1
        elif runs_in_window >= settings.public_demo_max_runs_per_hour:
            raise HTTPException(status_code=429, detail="public demo rate limit exceeded")
        else:
            runs_in_window += 1
        conn.execute(
            "UPDATE public_demo_tenants SET window_started_at=%s,runs_in_window=%s,"
            "last_run_at=%s,expires_at=%s WHERE visitor_ref=%s",
            (
                window_started_at,
                runs_in_window,
                now,
                now + timedelta(hours=settings.public_demo_ttl_hours),
                visitor_ref,
            ),
        )
        return str(existing[0])


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
    return _run_for_tenant(_demo_tenant(tenant_id))


@router.post("/public/run", response_model=PublicDemoResult)
def run_public_demo(request: PublicDemoRequest) -> PublicDemoResult:
    if not settings.demo_enabled:
        raise HTTPException(status_code=404, detail="demo is disabled")
    result = _run_for_tenant(_public_demo_tenant(request.visitor_ref))
    share = create_share(
        result.tenant_id,
        result.session_id,
        ShareRequest(expires_in_hours=settings.public_demo_ttl_hours),
    )
    return PublicDemoResult(
        **result.model_dump(),
        share_path=share.share_path,
        expires_at=share.expires_at,
    )


def _run_for_tenant(demo_tenant_id: str) -> DemoResult:
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
    ingest_events(demo_tenant_id, [event])
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
