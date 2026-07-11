"""Persist an AWS scan into the identity graph (blueprint 4.2).

Idempotent per (tenant, provider): principals, credentials, resources, and the
agent nodes are upserted by natural key; permissions and edges for this
provider are deleted and reinserted each scan so a re-scan converges instead
of duplicating. Credentials store fingerprints only - never secret values.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from abx_scanner.attribution import is_probable_agent
from abx_scanner.aws import AwsScanResult, Principal
from abx_scanner.policy import is_destructive, normalize_resource


def persist(conn: psycopg.Connection, tenant_id: str, result: AwsScanResult) -> None:
    provider = "aws"
    # Clear this provider's derived edges/permissions; nodes are upserted.
    conn.execute(
        "DELETE FROM permission_reaches_resource WHERE permission_id IN "
        "(SELECT id FROM permissions WHERE tenant_id = %s AND provider = %s)",
        (tenant_id, provider),
    )
    conn.execute(
        "DELETE FROM permissions WHERE tenant_id = %s AND provider = %s",
        (tenant_id, provider),
    )

    for principal in result.principals:
        principal_id = _upsert_principal(conn, tenant_id, principal)
        agent_id = _maybe_upsert_agent(conn, tenant_id, principal)
        for key in principal.access_keys:
            cred_id = _upsert_credential(conn, tenant_id, principal_id, key)
            if agent_id is not None:
                conn.execute(
                    "INSERT INTO agent_holds_credential (agent_id, credential_id, inferred_from) "
                    "VALUES (%s, %s, 'scan') ON CONFLICT DO NOTHING",
                    (agent_id, cred_id),
                )
        _persist_permissions(conn, tenant_id, principal, principal_id)

    conn.commit()


def _upsert_principal(conn: psycopg.Connection, tenant_id: str, p: Principal) -> str:
    row = conn.execute(
        "INSERT INTO principals (tenant_id, provider, kind, external_id) "
        "VALUES (%s, 'aws', %s, %s) "
        "ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET kind = EXCLUDED.kind "
        "RETURNING id",
        (tenant_id, p.kind, p.arn),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _maybe_upsert_agent(conn: psycopg.Connection, tenant_id: str, p: Principal) -> str | None:
    if not is_probable_agent(p):
        return None
    row = conn.execute(
        "INSERT INTO agents (tenant_id, name, framework, environment, status, last_seen) "
        "VALUES (%s, %s, '', 'unknown', 'active', now()) "
        "ON CONFLICT (tenant_id, name) DO UPDATE SET last_seen = now() "
        "RETURNING id",
        (tenant_id, p.name),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _upsert_credential(
    conn: psycopg.Connection, tenant_id: str, principal_id: str, key: Any
) -> str:
    status = "inactive" if key.status == "Inactive" else "active"
    row = conn.execute(
        "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, owner_principal, "
        "created_at_provider, last_used_at, status, last_scanned) "
        "VALUES (%s, 'aws', 'access_key', %s, %s, %s, %s, %s, now()) "
        "ON CONFLICT (tenant_id, provider, fingerprint) DO UPDATE SET "
        "last_used_at = EXCLUDED.last_used_at, status = EXCLUDED.status, "
        "owner_principal = EXCLUDED.owner_principal, last_scanned = now() "
        "RETURNING id",
        (tenant_id, key.access_key_id, principal_id, key.created_at, key.last_used_at, status),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _persist_permissions(
    conn: psycopg.Connection, tenant_id: str, principal: Principal, principal_id: str
) -> None:
    for policy in principal.policies:
        for grant in policy.grants:
            perm_row = conn.execute(
                "INSERT INTO permissions (tenant_id, principal_id, provider, scope, raw) "
                "VALUES (%s, %s, 'aws', %s, %s) RETURNING id",
                (
                    tenant_id,
                    principal_id,
                    grant.action,
                    Jsonb({"policy": policy.name, "resource": grant.resource}),
                ),
            ).fetchone()
            assert perm_row is not None
            perm_id = str(perm_row[0])

            identifier, prov, kind, env = normalize_resource(grant.resource)
            res_row = conn.execute(
                "INSERT INTO resources (tenant_id, provider, kind, identifier, environment) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (tenant_id, provider, identifier) DO UPDATE SET kind = EXCLUDED.kind "
                "RETURNING id",
                (tenant_id, prov, kind, identifier, env),
            ).fetchone()
            assert res_row is not None
            access = "admin" if grant.action in ("*",) else (
                "write" if is_destructive(grant.action) else "read"
            )
            conn.execute(
                "INSERT INTO permission_reaches_resource (permission_id, resource_id, access) "
                "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (perm_id, str(res_row[0]), access),
            )
