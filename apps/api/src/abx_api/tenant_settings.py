"""Tenant settings, scoped token lifecycle, and immutable redaction posture."""

from __future__ import annotations

import contextlib
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from psycopg import Connection
from pydantic import BaseModel, Field, StringConstraints

from abx_api.admin_audit import record_admin_action
from abx_api.auth import new_ingest_token, new_scan_token
from abx_api.ingest import ingest_events
from abx_api.rbac import ROLE_CAPABILITIES, new_read_token, require_configure
from abx_api.redaction import RULES, redact
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/settings", dependencies=[Depends(require_configure)])


class MemberView(BaseModel):
    user_ref: str
    role: str = "owner"


class TokenView(BaseModel):
    id: str
    kind: Literal["recording", "local_scan"]
    label: str
    created_at: str
    revoked_at: str | None
    captured_payload_events_today: int | None
    daily_payload_limit: int | None
    payload_allowance_state: Literal["unlimited", "available", "exhausted"] | None


class UsageView(BaseModel):
    day: str
    events: int
    daily_event_plan_threshold: int | None
    remaining_plan_events: int | None
    plan_state: Literal["unlimited", "within_plan", "over_plan"]


class SettingsView(BaseModel):
    tenant_id: str
    tenant_name: str
    created_at: str
    members: list[MemberView]
    tokens: list[TokenView]
    retention_days: int
    capture_payloads: bool
    # Read-only to tenants by design: a tenant that could switch compliance
    # mode off could also lower the floor it exists to enforce. Operator-set,
    # like plan assignment.
    compliance_mode: bool
    retention_floor_days: int
    redaction_rules: list[str]
    plan_key: str
    usage: UsageView


class SettingsUpdate(BaseModel):
    tenant_name: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)
    ]
    retention_days: int = Field(ge=1, le=3650)
    capture_payloads: bool


class TokenCreate(BaseModel):
    kind: Literal["recording", "local_scan"]
    label: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)
    ]
    # The dashboard identity minting this token becomes the operator of record
    # for everything recorded with it (EU AI Act Article 12). Omitted means the
    # token records unattributed, which the evidence pack reports as such.
    operator_user_ref: str | None = None


class ReadTokenCreate(BaseModel):
    label: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)
    ]
    role: Literal["viewer", "responder", "admin", "auditor"]


class TokenCreated(BaseModel):
    id: str
    kind: str
    label: str
    token: str


@router.get("", response_model=SettingsView)
def get_settings(tenant_id: str) -> SettingsView:
    with pg_pool().connection() as conn:
        tenant = conn.execute(
            "SELECT name,created_at FROM tenants WHERE id=%s", (tenant_id,)
        ).fetchone()
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        configured = conn.execute(
            "SELECT retention_days,capture_payloads,compliance_mode,retention_floor_days "
            "FROM tenant_settings WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        usage_row = conn.execute(
            "SELECT COALESCE(p.plan_key,'unlimited'),p.daily_event_limit,"
            "COALESCE(m.events,0),CURRENT_DATE FROM tenants t "
            "LEFT JOIN tenant_plans p ON p.tenant_id=t.id "
            "LEFT JOIN metering_daily m ON m.tenant_id=t.id AND m.day=CURRENT_DATE "
            "WHERE t.id=%s",
            (tenant_id,),
        ).fetchone()
        assert usage_row is not None
        members = conn.execute(
            "SELECT user_ref FROM tenant_members WHERE tenant_id=%s "
            "UNION SELECT m.user_ref FROM demo_tenants d JOIN tenant_members m "
            "ON m.tenant_id=d.owner_tenant_id WHERE d.demo_tenant_id=%s ORDER BY user_ref",
            (tenant_id, tenant_id),
        ).fetchall()
        tokens = conn.execute(
            "SELECT i.id,'recording',i.label,i.created_at,i.revoked_at,"
            "COALESCE(mt.captured_payload_events,0),p.per_token_daily_payload_limit "
            "FROM ingest_tokens i LEFT JOIN metering_token_daily mt "
            "ON mt.tenant_id=i.tenant_id AND mt.token_id=i.id AND mt.day=CURRENT_DATE "
            "LEFT JOIN tenant_plans p ON p.tenant_id=i.tenant_id "
            "WHERE i.tenant_id=%s UNION ALL "
            "SELECT id,'local_scan',label,created_at,revoked_at,NULL::bigint,NULL::bigint "
            "FROM scan_upload_tokens "
            "WHERE tenant_id=%s ORDER BY created_at DESC",
            (tenant_id, tenant_id),
        ).fetchall()
    retention_days, capture_payloads, compliance_mode, retention_floor_days = (
        configured or (30, True, False, 180)
    )
    plan_key = str(usage_row[0])
    daily_event_limit = int(usage_row[1]) if usage_row[1] is not None else None
    events = int(usage_row[2])
    return SettingsView(
        tenant_id=tenant_id,
        tenant_name=str(tenant[0]),
        created_at=tenant[1].isoformat(),
        members=[MemberView(user_ref=str(row[0])) for row in members],
        tokens=[
            TokenView(
                id=str(row[0]),
                kind=row[1],
                label=row[2],
                created_at=row[3].isoformat(),
                revoked_at=row[4].isoformat() if row[4] else None,
                captured_payload_events_today=(int(row[5]) if row[5] is not None else None),
                daily_payload_limit=(int(row[6]) if row[6] is not None else None),
                payload_allowance_state=(
                    None
                    if row[1] == "local_scan"
                    else "unlimited"
                    if row[6] is None
                    else "exhausted"
                    if int(row[5]) >= int(row[6])
                    else "available"
                ),
            )
            for row in tokens
        ],
        retention_days=int(retention_days),
        compliance_mode=bool(compliance_mode),
        retention_floor_days=int(retention_floor_days),
        capture_payloads=bool(capture_payloads),
        redaction_rules=[rule.id for rule in RULES],
        plan_key=plan_key,
        usage=UsageView(
            day=usage_row[3].isoformat(),
            events=events,
            daily_event_plan_threshold=daily_event_limit,
            remaining_plan_events=(
                max(daily_event_limit - events, 0)
                if daily_event_limit is not None
                else None
            ),
            plan_state=(
                "unlimited"
                if daily_event_limit is None
                else "over_plan"
                if events > daily_event_limit
                else "within_plan"
            ),
        ),
    )


@router.put("", response_model=SettingsView)
def update_settings(tenant_id: str, update: SettingsUpdate) -> SettingsView:
    with pg_pool().connection() as conn:
        tenant = conn.execute(
            "UPDATE tenants SET name=%s WHERE id=%s RETURNING id",
            (update.tenant_name, tenant_id),
        ).fetchone()
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        current = conn.execute(
            "SELECT compliance_mode,retention_floor_days FROM tenant_settings "
            "WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        compliance_mode = bool(current[0]) if current else False
        floor = int(current[1]) if current else 180
        # Article 12 mandates a retention minimum. A tenant in compliance mode
        # cannot go below it by any API path. The refusal is chained AFTER this
        # transaction closes: ingest takes its own pool connection and locks the
        # same tenant row, so recording in here deadlocks against the UPDATE
        # above and hangs the request forever.
        refused = compliance_mode and update.retention_days < floor
        if not refused:
            conn.execute(
                "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads) "
                "VALUES (%s,%s,%s) ON CONFLICT (tenant_id) DO UPDATE SET "
                "retention_days=EXCLUDED.retention_days,"
                "capture_payloads=EXCLUDED.capture_payloads,"
                "updated_at=now()",
                (tenant_id, update.retention_days, update.capture_payloads),
            )
    if refused:
        record_retention_refusal(tenant_id, update.retention_days, floor)
        raise HTTPException(
            status_code=409,
            detail=(
                f"retention_days {update.retention_days} is below the "
                f"{floor}-day compliance floor in force for this tenant"
            ),
        )
    record_admin_action(
        tenant_id, "settings updated", "tenant_settings",
        {"retention_days": update.retention_days,
         "capture_payloads": update.capture_payloads},
    )
    return get_settings(tenant_id)


def record_retention_refusal(tenant_id: str, requested: int, floor: int) -> None:
    """Chain a refused retention change (EU AI Act Article 12).

    The attempt matters evidentially: an auditor asking whether anyone tried to
    shorten the record below the mandated floor must be able to get a real
    answer, and that answer has to be as tamper-evident as the events it
    protects. Recording must never block the refusal itself, so a failure here
    degrades to a rejected request rather than a served one.
    """
    event = IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "abx-admin",
        "session_id": f"retention-policy:{uuid.uuid4()}", "seq": 0,
        "ts": datetime.now(UTC), "source": "admin_api", "event_type": "agent_step",
        "operation": {
            "name": "retention change refused", "provider": "leaflyst",
            "target": "tenant_settings.retention_days", "outcome": "denied",
            "duration_ms": 0,
        },
        "resource_refs": [f"abx:retention-floor:{floor}"],
        "payload": json.dumps({"requested_days": requested, "floor_days": floor}),
    })
    with contextlib.suppress(Exception):
        ingest_events(tenant_id, [event])


def operator_fingerprint(user_ref: str) -> str:
    """sha256 of the lowercased identity, never the address itself.

    Personal data gets the same treatment as secrets: a fingerprint is enough
    to prove two events share an operator, so an erasure request can drop the
    operators row without ever touching the event chain.
    """
    return hashlib.sha256(user_ref.strip().lower().encode()).hexdigest()


def upsert_operator(conn: Connection, tenant_id: str, user_ref: str) -> str:
    """Resolve a dashboard identity to a tenant-scoped operator id."""
    row = conn.execute(
        "INSERT INTO operators (tenant_id,user_ref,email_fingerprint) VALUES (%s,%s,%s) "
        "ON CONFLICT (tenant_id,user_ref) DO UPDATE SET last_seen=now() RETURNING id",
        (tenant_id, user_ref, operator_fingerprint(user_ref)),
    ).fetchone()
    assert row is not None
    return str(row[0])


@router.post("/read-tokens", response_model=TokenCreated)
def create_read_token(tenant_id: str, request: ReadTokenCreate) -> TokenCreated:
    """Mint a tenant-BOUND read token with an explicit role.

    Replaces reaching for the shared operator key. The token carries its tenant,
    so it cannot be pointed at another one, and its role, so an auditor handed
    one cannot change anything.
    """
    if request.role not in ROLE_CAPABILITIES:
        raise HTTPException(status_code=422, detail="unknown role")
    token, token_hash = new_read_token()
    label, _ = redact(request.label)
    with pg_pool().connection() as conn:
        tenant = conn.execute("SELECT 1 FROM tenants WHERE id=%s", (tenant_id,)).fetchone()
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        row = conn.execute(
            "INSERT INTO read_tokens (tenant_id,token_hash,label,role) "
            "VALUES (%s,%s,%s,%s) RETURNING id",
            (tenant_id, token_hash, label, request.role),
        ).fetchone()
    assert row is not None
    record_admin_action(
        tenant_id, "read token issued", str(row[0]),
        {"label": label, "role": request.role},
    )
    return TokenCreated(id=str(row[0]), kind="read", label=label, token=token)


@router.post("/read-tokens/{token_id}/revoke")
def revoke_read_token(tenant_id: str, token_id: UUID) -> dict[str, str]:
    with pg_pool().connection() as conn:
        row = conn.execute(
            "UPDATE read_tokens SET revoked_at=now() WHERE tenant_id=%s AND id=%s "
            "AND revoked_at IS NULL RETURNING id",
            (tenant_id, token_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="read token not found")
    record_admin_action(tenant_id, "read token revoked", str(token_id))
    return {"status": "revoked"}


@router.post("/tokens", response_model=TokenCreated)
def create_token(tenant_id: str, request: TokenCreate) -> TokenCreated:
    token, token_hash = (
        new_ingest_token() if request.kind == "recording" else new_scan_token()
    )
    label, _ = redact(request.label)
    table = "ingest_tokens" if request.kind == "recording" else "scan_upload_tokens"
    with pg_pool().connection() as conn:
        tenant = conn.execute("SELECT 1 FROM tenants WHERE id=%s", (tenant_id,)).fetchone()
        if tenant is None:
            raise HTTPException(status_code=404, detail="tenant not found")
        if request.kind == "recording" and request.operator_user_ref:
            operator_id = upsert_operator(conn, tenant_id, request.operator_user_ref)
            row = conn.execute(
                "INSERT INTO ingest_tokens (tenant_id,token_hash,label,operator_id) "
                "VALUES (%s,%s,%s,%s) RETURNING id",
                (tenant_id, token_hash, label, operator_id),
            ).fetchone()
        else:
            row = conn.execute(
                f"INSERT INTO {table} (tenant_id,token_hash,label) "  # noqa: S608
                "VALUES (%s,%s,%s) RETURNING id",
                (tenant_id, token_hash, label),
            ).fetchone()
    assert row is not None
    record_admin_action(
        tenant_id, "token issued", str(row[0]),
        {"kind": request.kind, "label": label},
    )
    return TokenCreated(
        id=str(row[0]), kind=request.kind, label=label, token=token
    )


@router.post("/tokens/{kind}/{token_id}/revoke")
def revoke_token(
    tenant_id: str,
    kind: Literal["recording", "local_scan"],
    token_id: UUID,
) -> dict[str, str]:
    table = "ingest_tokens" if kind == "recording" else "scan_upload_tokens"
    with pg_pool().connection() as conn:
        row = conn.execute(
            f"UPDATE {table} SET revoked_at=COALESCE(revoked_at,now()) "  # noqa: S608
            "WHERE tenant_id=%s AND id=%s RETURNING id",
            (tenant_id, token_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="token not found")
    return {"status": "revoked"}
