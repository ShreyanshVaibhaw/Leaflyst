"""Roles, capabilities, and per-tenant scoped read tokens (plan2 phase 23).

Four roles, chosen from how the product is actually used rather than from a
generic hierarchy:

    viewer     read findings, sessions, replay
    responder  everything viewer may, plus revoke a credential
    admin      everything, including configuration and token issuance
    auditor    read everything INCLUDING evidence export, change nothing

The auditor role is not decoration. It is what an external assessor is handed
during a compliance review, which is why it must be a real role rather than an
admin account plus a promise: an assessor who *could* alter configuration
undermines the independence of the assessment they are performing.

Roles are not a strict ladder. An auditor can export evidence a responder
cannot, and a responder can revoke a credential an auditor must not touch, so
capability is a set per role rather than a rank comparison.

Two ways to authenticate:

- `X-Abx-Admin-Key`, the operator key. Unbound to any tenant, which is exactly
  the weakness this phase exists to reduce; it stays for operator tooling and
  local development.
- `Authorization: Bearer abx_read_...`, a scoped read token. It BINDS its
  tenant, so a caller cannot ask for another tenant's data by changing a query
  parameter - isolation by construction rather than by care.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from fastapi import Header, HTTPException

from abx_api.settings import settings
from abx_api.store import pg_pool

READ_TOKEN_PREFIX = "abx_read_"


class Capability(StrEnum):
    READ = "read"
    EXPORT_EVIDENCE = "export_evidence"
    REVOKE = "revoke"
    TRIAGE = "triage"
    CONFIGURE = "configure"


ROLE_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "viewer": frozenset({Capability.READ}),
    "responder": frozenset({Capability.READ, Capability.REVOKE, Capability.TRIAGE}),
    "auditor": frozenset({Capability.READ, Capability.EXPORT_EVIDENCE}),
    "admin": frozenset(Capability),
}


@dataclass(frozen=True)
class Principal:
    """Who is calling, and what they may do."""

    role: str
    # None for the operator key, which is not bound to a tenant. A bound
    # principal may only ever act on its own tenant.
    tenant_id: str | None
    token_id: str | None = None

    @property
    def capabilities(self) -> frozenset[Capability]:
        return ROLE_CAPABILITIES.get(self.role, frozenset())

    def may(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def scoped_to(self, tenant_id: str) -> bool:
        return self.tenant_id is None or self.tenant_id == tenant_id


def new_read_token() -> tuple[str, str]:
    """Returns (token, token_hash). The token is shown once and never stored."""
    token = READ_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def resolve_principal(admin_key: str, authorization: str) -> Principal:
    """Identify the caller, preferring a scoped token over the shared key."""
    token = authorization.removeprefix("Bearer ").strip()
    if token.startswith(READ_TOKEN_PREFIX):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with pg_pool().connection() as conn:
            row = conn.execute(
                "SELECT id, tenant_id, role, expires_at FROM read_tokens "
                "WHERE token_hash = %s AND revoked_at IS NULL",
                (token_hash,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="invalid read token")
        expires_at = row[3]
        if expires_at is not None:
            deadline = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=UTC)
            if deadline <= datetime.now(UTC):
                raise HTTPException(status_code=401, detail="read token expired")
        return Principal(role=str(row[2]), tenant_id=str(row[1]), token_id=str(row[0]))

    if admin_key and hmac.compare_digest(admin_key, settings.admin_key):
        return Principal(role="admin", tenant_id=None)

    raise HTTPException(status_code=401, detail="authentication required")


def require(capability: Capability) -> Callable[..., Principal]:
    """Dependency enforcing one capability, and tenant binding with it.

    Both checks live together on purpose. Splitting them is how a route ends up
    correctly checking permission and then reading the wrong tenant's data.
    """

    def dependency(
        tenant_id: str = "",
        x_abx_admin_key: str = Header(default=""),
        authorization: str = Header(default=""),
    ) -> Principal:
        principal = resolve_principal(x_abx_admin_key, authorization)
        if not principal.may(capability):
            raise HTTPException(
                status_code=403,
                detail=f"role '{principal.role}' may not {capability.value}",
            )
        if tenant_id and not principal.scoped_to(tenant_id):
            # A bound token asking for someone else's tenant is the attack this
            # phase closes; 404 rather than 403 so it cannot be used to probe
            # which tenant ids exist.
            raise HTTPException(status_code=404, detail="not found")
        return principal

    # Lets the route-guard inventory read a route's capability off the resolved
    # dependency instead of matching on the name it was bound under. The two
    # guard defects found on August 2 both hid behind a stale alias name whose
    # value had been changed underneath it.
    dependency.abx_capability = capability  # type: ignore[attr-defined]
    return dependency


require_read = require(Capability.READ)
require_export = require(Capability.EXPORT_EVIDENCE)
require_revoke = require(Capability.REVOKE)
require_triage = require(Capability.TRIAGE)
require_configure = require(Capability.CONFIGURE)
