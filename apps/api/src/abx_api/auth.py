"""Ingest-token and admin-key authentication.

Ingest tokens are write-only by construction: this module resolves a token to a
tenant_id for POST /v1/ingest and nothing else; no read endpoint accepts them.
Only the sha256 of a token is ever stored (ingest_tokens.token_hash).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException

from abx_api.settings import settings
from abx_api.store import pg_pool

TOKEN_PREFIX = "abx_ingest_"
SCAN_TOKEN_PREFIX = "abx_scan_"


@dataclass(frozen=True)
class IngestIdentity:
    tenant_id: str
    token_id: str


def new_ingest_token() -> tuple[str, str]:
    """Returns (token, token_hash). The token is shown once and never stored."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def new_scan_token() -> tuple[str, str]:
    """Returns a scan-upload token that cannot ingest events or read data."""
    token = SCAN_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def ingest_identity_from_token(authorization: str = Header(default="")) -> IngestIdentity:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT tenant_id,id FROM ingest_tokens "
            "WHERE token_hash = %s AND revoked_at IS NULL",
            (token_hash,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="invalid ingest token")
    return IngestIdentity(tenant_id=str(row[0]), token_id=str(row[1]))


def tenant_from_scan_token(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token_hash = hashlib.sha256(authorization.removeprefix("Bearer ").strip().encode()).hexdigest()
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT tenant_id FROM scan_upload_tokens WHERE token_hash=%s AND revoked_at IS NULL",
            (token_hash,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="invalid scan token")
    return str(row[0])


def require_admin(x_abx_admin_key: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_abx_admin_key, settings.admin_key):
        raise HTTPException(status_code=401, detail="invalid admin key")
