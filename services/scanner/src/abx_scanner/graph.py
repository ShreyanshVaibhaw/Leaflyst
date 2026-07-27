"""Persist an AWS scan into the identity graph (blueprint 4.2).

Idempotent per (tenant, provider): principals, credentials, resources, and the
agent nodes are upserted by natural key; permissions and edges for this
provider are deleted and reinserted each scan so a re-scan converges instead
of duplicating. Credentials store fingerprints only - never secret values.
"""

from __future__ import annotations

import re
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from abx_scanner.attribution import is_probable_agent
from abx_scanner.aws import AwsScanResult, Principal
from abx_scanner.gcp import GcpGrant, GcpKey, GcpScanResult, GcpServiceAccount
from abx_scanner.github import GitHubScanResult
from abx_scanner.policy import is_destructive, normalize_resource

_AGENTY_LOGIN = re.compile(
    r"(?i)(svc|service|agent|bot|mcp|worker|automation|deploy|langgraph|langchain)"
)


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


def persist_github(conn: psycopg.Connection, tenant_id: str, result: GitHubScanResult) -> None:
    """Persist a GitHub scan. Idempotent per (tenant, provider='github')."""
    provider = "github"
    conn.execute(
        "DELETE FROM permission_reaches_resource WHERE permission_id IN "
        "(SELECT id FROM permissions WHERE tenant_id = %s AND provider = %s)",
        (tenant_id, provider),
    )
    conn.execute(
        "DELETE FROM permissions WHERE tenant_id = %s AND provider = %s",
        (tenant_id, provider),
    )

    for cred in result.credentials:
        principal_id = _upsert_gh_principal(
            conn, tenant_id, cred.owner_kind, cred.owner_login
        )
        cred_id = _upsert_gh_credential(conn, tenant_id, principal_id, cred)
        agent_id = _maybe_upsert_gh_agent(conn, tenant_id, cred)
        if agent_id is not None:
            conn.execute(
                "INSERT INTO agent_holds_credential (agent_id, credential_id, inferred_from) "
                "VALUES (%s, %s, 'scan') ON CONFLICT DO NOTHING",
                (agent_id, cred_id),
            )
        for perm, access in cred.permissions.items():
            _persist_gh_permission(
                conn, tenant_id, principal_id, cred_id, perm, access, cred
            )

    conn.commit()


def persist_gcp(conn: psycopg.Connection, tenant_id: str, result: GcpScanResult) -> None:
    """Persist fingerprints and IAM reach from a read-only Google Cloud scan."""
    provider = "gcp"
    conn.execute(
        "DELETE FROM permission_reaches_resource WHERE permission_id IN "
        "(SELECT id FROM permissions WHERE tenant_id = %s AND provider = %s)",
        (tenant_id, provider),
    )
    conn.execute(
        "DELETE FROM permissions WHERE tenant_id = %s AND provider = %s",
        (tenant_id, provider),
    )

    for account in result.service_accounts:
        principal_id = _upsert_gcp_principal(conn, tenant_id, account)
        agent_id = _upsert_gcp_agent(conn, tenant_id, account)
        for key in account.keys:
            credential_id = _upsert_gcp_credential(
                conn, tenant_id, principal_id, key
            )
            conn.execute(
                "INSERT INTO agent_holds_credential (agent_id, credential_id, inferred_from) "
                "VALUES (%s, %s, 'scan') ON CONFLICT DO NOTHING",
                (agent_id, credential_id),
            )
        for grant in account.grants:
            _persist_gcp_permission(conn, tenant_id, principal_id, grant)
    conn.commit()


def _upsert_gcp_principal(
    conn: psycopg.Connection, tenant_id: str, account: GcpServiceAccount
) -> str:
    row = conn.execute(
        "INSERT INTO principals (tenant_id, provider, kind, external_id) "
        "VALUES (%s, 'gcp', 'service_account', %s) "
        "ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET "
        "kind = EXCLUDED.kind RETURNING id",
        (tenant_id, account.email),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _upsert_gcp_agent(
    conn: psycopg.Connection, tenant_id: str, account: GcpServiceAccount
) -> str:
    row = conn.execute(
        "INSERT INTO agents (tenant_id, name, framework, environment, status, last_seen) "
        "VALUES (%s, %s, '', 'unknown', 'active', now()) "
        "ON CONFLICT (tenant_id, name) DO UPDATE SET last_seen = now(), status = 'active' "
        "RETURNING id",
        (tenant_id, f"gcp:{account.email}"),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _upsert_gcp_credential(
    conn: psycopg.Connection,
    tenant_id: str,
    principal_id: str,
    key: GcpKey,
) -> str:
    status = "inactive" if key.disabled else "active"
    row = conn.execute(
        "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, owner_principal, "
        "created_at_provider, status, last_scanned) "
        "VALUES (%s, 'gcp', 'service_account_key', %s, %s, %s, %s, now()) "
        "ON CONFLICT (tenant_id, provider, fingerprint) DO UPDATE SET "
        "created_at_provider = EXCLUDED.created_at_provider, status = EXCLUDED.status, "
        "owner_principal = EXCLUDED.owner_principal, last_scanned = now() RETURNING id",
        (tenant_id, key.fingerprint, principal_id, key.created_at, status),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _persist_gcp_permission(
    conn: psycopg.Connection,
    tenant_id: str,
    principal_id: str,
    grant: GcpGrant,
) -> None:
    permission = conn.execute(
        "INSERT INTO permissions (tenant_id, principal_id, provider, scope, raw) "
        "VALUES (%s, %s, 'gcp', %s, %s) RETURNING id",
        (
            tenant_id,
            principal_id,
            grant.role,
            Jsonb({"resource_kind": grant.resource_kind}),
        ),
    ).fetchone()
    assert permission is not None
    resource = conn.execute(
        "INSERT INTO resources (tenant_id, provider, kind, identifier, environment) "
        "VALUES (%s, 'gcp', %s, %s, 'unknown') "
        "ON CONFLICT (tenant_id, provider, identifier) DO UPDATE SET "
        "kind = EXCLUDED.kind RETURNING id",
        (tenant_id, grant.resource_kind, grant.resource),
    ).fetchone()
    assert resource is not None
    conn.execute(
        "INSERT INTO permission_reaches_resource (permission_id, resource_id, access) "
        "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
        (str(permission[0]), str(resource[0]), grant.access),
    )


def _upsert_gh_principal(
    conn: psycopg.Connection, tenant_id: str, kind: str, login: str
) -> str:
    row = conn.execute(
        "INSERT INTO principals (tenant_id, provider, kind, external_id) "
        "VALUES (%s, 'github', %s, %s) "
        "ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET kind = EXCLUDED.kind "
        "RETURNING id",
        (tenant_id, kind, login),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _upsert_gh_credential(
    conn: psycopg.Connection, tenant_id: str, principal_id: str, cred: Any
) -> str:
    row = conn.execute(
        "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, owner_principal, "
        "created_at_provider, last_used_at, status, last_scanned) "
        "VALUES (%s, 'github', %s, %s, %s, %s, %s, 'active', now()) "
        "ON CONFLICT (tenant_id, provider, fingerprint) DO UPDATE SET "
        "last_used_at = EXCLUDED.last_used_at, owner_principal = EXCLUDED.owner_principal, "
        "last_scanned = now() RETURNING id",
        (tenant_id, cred.kind, cred.fingerprint, principal_id,
         cred.created_at, cred.last_used_at),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _maybe_upsert_gh_agent(conn: psycopg.Connection, tenant_id: str, cred: Any) -> str | None:
    # App installations and service-owned PATs are agent-like; deploy keys are
    # repo automation. Attribute app installations and agenty-named owners.
    name = cred.owner_login
    agenty = cred.owner_kind == "gh_app" or _AGENTY_LOGIN.search(name)
    if not agenty:
        return None
    row = conn.execute(
        "INSERT INTO agents (tenant_id, name, framework, environment, status, last_seen) "
        "VALUES (%s, %s, '', 'unknown', 'active', now()) "
        "ON CONFLICT (tenant_id, name) DO UPDATE SET last_seen = now() RETURNING id",
        (tenant_id, f"github:{name}"),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _persist_gh_permission(
    conn: psycopg.Connection, tenant_id: str, principal_id: str, credential_id: str,
    perm: str, access: str, cred: Any,
) -> None:
    perm_row = conn.execute(
        "INSERT INTO permissions "
        "(tenant_id, credential_id, principal_id, provider, scope, raw) "
        "VALUES (%s, %s, %s, 'github', %s, %s) RETURNING id",
        (tenant_id, credential_id, principal_id, f"{perm}:{access}",
         Jsonb({"kind": cred.kind, "fingerprint": cred.fingerprint})),
    ).fetchone()
    assert perm_row is not None
    perm_id = str(perm_row[0])
    for repo in cred.reachable_repos or ["gh:repo:*"]:
        res_row = conn.execute(
            "INSERT INTO resources (tenant_id, provider, kind, identifier, environment) "
            "VALUES (%s, 'github', 'repo', %s, 'unknown') "
            "ON CONFLICT (tenant_id, provider, identifier) DO UPDATE SET kind = EXCLUDED.kind "
            "RETURNING id",
            (tenant_id, repo),
        ).fetchone()
        assert res_row is not None
        conn.execute(
            "INSERT INTO permission_reaches_resource (permission_id, resource_id, access) "
            "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (perm_id, str(res_row[0]), access),
        )


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
