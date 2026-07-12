"""Tenant settings, scoped token lifecycle, and immutable redaction posture."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, StringConstraints

from abx_api.auth import new_ingest_token, new_scan_token, require_admin
from abx_api.redaction import RULES, redact
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/settings", dependencies=[Depends(require_admin)])


class MemberView(BaseModel):
    user_ref: str
    role: str = "owner"


class TokenView(BaseModel):
    id: str
    kind: Literal["recording", "local_scan"]
    label: str
    created_at: str
    revoked_at: str | None


class SettingsView(BaseModel):
    tenant_id: str
    tenant_name: str
    created_at: str
    members: list[MemberView]
    tokens: list[TokenView]
    retention_days: int
    capture_payloads: bool
    redaction_rules: list[str]


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
            "SELECT retention_days,capture_payloads FROM tenant_settings WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        members = conn.execute(
            "SELECT user_ref FROM tenant_members WHERE tenant_id=%s "
            "UNION SELECT m.user_ref FROM demo_tenants d JOIN tenant_members m "
            "ON m.tenant_id=d.owner_tenant_id WHERE d.demo_tenant_id=%s ORDER BY user_ref",
            (tenant_id, tenant_id),
        ).fetchall()
        tokens = conn.execute(
            "SELECT id,'recording',label,created_at,revoked_at FROM ingest_tokens "
            "WHERE tenant_id=%s UNION ALL "
            "SELECT id,'local_scan',label,created_at,revoked_at FROM scan_upload_tokens "
            "WHERE tenant_id=%s ORDER BY created_at DESC",
            (tenant_id, tenant_id),
        ).fetchall()
    retention_days, capture_payloads = configured or (30, True)
    return SettingsView(
        tenant_id=tenant_id,
        tenant_name=str(tenant[0]),
        created_at=tenant[1].isoformat(),
        members=[MemberView(user_ref=str(row[0])) for row in members],
        tokens=[TokenView(
            id=str(row[0]), kind=row[1], label=row[2],
            created_at=row[3].isoformat(),
            revoked_at=row[4].isoformat() if row[4] else None,
        ) for row in tokens],
        retention_days=int(retention_days),
        capture_payloads=bool(capture_payloads),
        redaction_rules=[rule.id for rule in RULES],
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
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads) "
            "VALUES (%s,%s,%s) ON CONFLICT (tenant_id) DO UPDATE SET "
            "retention_days=EXCLUDED.retention_days,capture_payloads=EXCLUDED.capture_payloads,"
            "updated_at=now()",
            (tenant_id, update.retention_days, update.capture_payloads),
        )
    return get_settings(tenant_id)


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
        row = conn.execute(
            f"INSERT INTO {table} (tenant_id,token_hash,label) "  # noqa: S608
            "VALUES (%s,%s,%s) RETURNING id",
            (tenant_id, token_hash, label),
        ).fetchone()
    assert row is not None
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
