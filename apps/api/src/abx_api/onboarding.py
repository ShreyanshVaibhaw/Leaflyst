"""Idempotent self-serve tenant bootstrap called by the authenticated web app."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from abx_api.auth import new_ingest_token, new_scan_token, require_admin
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/onboarding", dependencies=[Depends(require_admin)])


class BootstrapRequest(BaseModel):
    user_ref: str = Field(min_length=1, max_length=512)
    tenant_name: str = Field(min_length=1, max_length=200)


class BootstrapResult(BaseModel):
    tenant_id: str
    ingest_token: str | None
    scan_token: str | None
    created: bool


class AuthorizationResult(BaseModel):
    authorized: bool


@router.get("/authorize", response_model=AuthorizationResult)
def authorize(user_ref: str, tenant_id: str) -> AuthorizationResult:
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT EXISTS("
            "SELECT 1 FROM tenant_members WHERE user_ref=%s AND tenant_id=%s "
            "UNION ALL "
            "SELECT 1 FROM demo_tenants d JOIN tenant_members m "
            "ON m.tenant_id=d.owner_tenant_id "
            "WHERE m.user_ref=%s AND d.demo_tenant_id=%s)",
            (user_ref, tenant_id, user_ref, tenant_id),
        ).fetchone()
    assert row is not None
    return AuthorizationResult(authorized=bool(row[0]))


@router.post("/bootstrap", response_model=BootstrapResult)
def bootstrap(request: BootstrapRequest) -> BootstrapResult:
    with pg_pool().connection() as conn:
        # Serialize retries for one identity so concurrent first-page submits
        # cannot create orphan tenants before the unique membership insert.
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (request.user_ref,))
        existing = conn.execute(
            "SELECT tenant_id FROM tenant_members WHERE user_ref=%s",
            (request.user_ref,),
        ).fetchone()
        if existing is not None:
            return BootstrapResult(
                tenant_id=str(existing[0]), ingest_token=None, scan_token=None, created=False
            )
        tenant = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (request.tenant_name.strip(),),
        ).fetchone()
        assert tenant is not None
        token, token_hash = new_ingest_token()
        scan_token, scan_token_hash = new_scan_token()
        conn.execute(
            "INSERT INTO tenant_members (user_ref, tenant_id) VALUES (%s, %s)",
            (request.user_ref, tenant[0]),
        )
        conn.execute(
            "INSERT INTO ingest_tokens (tenant_id, token_hash, label) "
            "VALUES (%s, %s, 'onboarding')",
            (tenant[0], token_hash),
        )
        conn.execute(
            "INSERT INTO scan_upload_tokens (tenant_id, token_hash, label) "
            "VALUES (%s, %s, 'onboarding')",
            (tenant[0], scan_token_hash),
        )
    return BootstrapResult(
        tenant_id=str(tenant[0]), ingest_token=token, scan_token=scan_token, created=True
    )
