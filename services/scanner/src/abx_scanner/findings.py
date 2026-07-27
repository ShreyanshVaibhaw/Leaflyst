"""Findings engine (blueprint 5.3).

Deterministic rules over the persisted graph. Each finding is typed, has a
natural key for dedup across scans, a severity, an evidence blob, and a
remediation. Runs entirely in SQL + Python over one tenant's AWS graph.

Rules (v0.1):
  orphaned_credential  - key unused >30d (or never) and inactive/no recent use
  over_privileged      - destructive/admin grant on wildcard or prod resources,
                         especially services Access Advisor shows unused
  stale_authorization  - key not rotated in >90d
  blast_radius         - per credential, the transitive resource reach
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

ORPHAN_DAYS = 30
STALE_ROTATION_DAYS = 90


@dataclass
class Finding:
    finding_type: str
    natural_key: str
    severity: str
    credential_id: str | None
    evidence: dict[str, Any]
    remediation: str


def _now() -> datetime:
    return datetime.now(UTC)


def compute_findings(conn: psycopg.Connection, tenant_id: str) -> list[Finding]:
    findings: list[Finding] = []
    creds = conn.execute(
        "SELECT c.id, c.fingerprint, c.last_used_at, c.created_at_provider, c.status, "
        "p.external_id, p.id "
        "FROM credentials c JOIN principals p ON c.owner_principal = p.id "
        "WHERE c.tenant_id = %s AND c.provider = 'aws'",
        (tenant_id,),
    ).fetchall()

    now = _now()
    for cred_id, fp, last_used, created, status, principal_arn, principal_id in creds:
        reach = _blast_radius(conn, str(principal_id))
        findings.extend(
            _rules_for_credential(
                str(cred_id), fp, last_used, created, status, str(principal_arn), reach, now
            )
        )
    return findings


def compute_github_findings(conn: psycopg.Connection, tenant_id: str) -> list[Finding]:
    findings: list[Finding] = []
    creds = conn.execute(
        "SELECT c.id, c.fingerprint, c.kind, c.last_used_at, c.created_at_provider, "
        "p.external_id, p.id "
        "FROM credentials c JOIN principals p ON c.owner_principal = p.id "
        "WHERE c.tenant_id = %s AND c.provider = 'github'",
        (tenant_id,),
    ).fetchall()

    now = _now()
    for cred_id, fp, kind, last_used, created, owner, _principal_id in creds:
        reach = _blast_radius_for_credential(conn, str(cred_id))
        findings.extend(
            _github_rules(str(cred_id), fp, kind, last_used, created, str(owner), reach, now)
        )
    return findings


def compute_gcp_findings(conn: psycopg.Connection, tenant_id: str) -> list[Finding]:
    findings: list[Finding] = []
    credentials = conn.execute(
        "SELECT c.id, c.fingerprint, c.created_at_provider, p.external_id, p.id "
        "FROM credentials c JOIN principals p ON c.owner_principal = p.id "
        "WHERE c.tenant_id = %s AND c.provider = 'gcp'",
        (tenant_id,),
    ).fetchall()
    now = _now()
    for credential_id, fingerprint, created, owner, principal_id in credentials:
        reach = _blast_radius(conn, str(principal_id))
        findings.extend(
            _gcp_rules(
                str(credential_id),
                str(fingerprint),
                created,
                str(owner),
                reach,
                now,
            )
        )
    return findings


def _gcp_rules(
    credential_id: str,
    fingerprint: str,
    created: datetime | None,
    owner: str,
    reach: dict[str, Any],
    now: datetime,
) -> list[Finding]:
    out: list[Finding] = []
    has_admin = "admin" in reach["access_levels"]
    has_write = "write" in reach["access_levels"]
    if has_admin or has_write:
        out.append(
            Finding(
                "over_privileged",
                f"gcp:overpriv:{fingerprint}",
                "critical" if has_admin else "high",
                credential_id,
                {
                    "fingerprint": fingerprint,
                    "owner": owner,
                    "scopes": reach["scopes"][:20],
                    "reachable_resources": reach["resources"][:20],
                    "reach_count": reach["count"],
                    "last_used_available": False,
                },
                "Replace this user-managed key where possible and reduce the service "
                "account to read-only or the minimum roles it needs.",
            )
        )
    if created is not None and (now - created).days > STALE_ROTATION_DAYS:
        out.append(
            Finding(
                "stale_authorization",
                f"gcp:stale:{fingerprint}",
                "medium",
                credential_id,
                {
                    "fingerprint": fingerprint,
                    "owner": owner,
                    "age_days": (now - created).days,
                    "last_used_available": False,
                },
                f"Rotate or remove this service-account key; it is over "
                f"{STALE_ROTATION_DAYS} days old.",
            )
        )
    out.append(
        Finding(
            "blast_radius",
            f"gcp:blast:{fingerprint}",
            "info",
            credential_id,
            {
                "fingerprint": fingerprint,
                "owner": owner,
                "reach_count": reach["count"],
                "resources": reach["resources"][:50],
                "last_used_available": False,
            },
            "Review what this service-account key can reach if compromised.",
        )
    )
    return out


def _github_rules(
    cred_id: str,
    fingerprint: str,
    kind: str,
    last_used: datetime | None,
    created: datetime | None,
    owner: str,
    reach: dict[str, Any],
    now: datetime,
) -> list[Finding]:
    out: list[Finding] = []
    unused_days = (now - last_used).days if last_used else None
    never_used = last_used is None
    label = kind.replace("_", " ")

    if never_used or (unused_days is not None and unused_days > ORPHAN_DAYS):
        out.append(Finding(
            "orphaned_credential",
            f"github:orphaned:{fingerprint}",
            "high" if reach["destructive"] else "medium",
            cred_id,
            {"fingerprint": fingerprint, "owner": owner, "kind": kind,
             "last_used_days_ago": unused_days, "never_used": never_used,
             "reach_count": reach["count"]},
            f"Remove the unused {label} owned by {owner} if no longer needed.",
        ))

    # Over-privileged: admin scope, or write access to repositories.
    has_admin = any(a == "admin" for a in reach["access_levels"])
    has_write = any(a == "write" for a in reach["access_levels"])
    if has_admin or has_write:
        out.append(Finding(
            "over_privileged",
            f"github:overpriv:{fingerprint}",
            "critical" if has_admin else "high",
            cred_id,
            {"fingerprint": fingerprint, "owner": owner, "kind": kind,
             "scopes": reach["scopes"][:20], "reachable_repos": reach["resources"][:20],
             "reach_count": reach["count"]},
            f"Scope this {label} to read-only or the minimum repositories it needs.",
        ))

    if created is not None and (now - created).days > STALE_ROTATION_DAYS:
        out.append(Finding(
            "stale_authorization",
            f"github:stale:{fingerprint}",
            "medium",
            cred_id,
            {"fingerprint": fingerprint, "owner": owner, "kind": kind,
             "age_days": (now - created).days},
            f"Rotate this {label}; it is over {STALE_ROTATION_DAYS} days old.",
        ))

    out.append(Finding(
        "blast_radius",
        f"github:blast:{fingerprint}",
        "info",
        cred_id,
        {"fingerprint": fingerprint, "owner": owner, "kind": kind,
         "reach_count": reach["count"], "resources": reach["resources"][:50]},
        "Review what this credential can reach if compromised.",
    ))
    return out


def _rules_for_credential(
    cred_id: str,
    fingerprint: str,
    last_used: datetime | None,
    created: datetime | None,
    status: str,
    principal_arn: str,
    reach: dict[str, Any],
    now: datetime,
) -> list[Finding]:
    out: list[Finding] = []
    unused_days = (now - last_used).days if last_used else None
    never_used = last_used is None

    # Orphaned: never used, or unused beyond the window.
    if never_used or (unused_days is not None and unused_days > ORPHAN_DAYS):
        sev = "high" if reach["destructive"] else "medium"
        out.append(Finding(
            "orphaned_credential",
            f"aws:orphaned:{fingerprint}",
            sev,
            cred_id,
            {
                "fingerprint": fingerprint,
                "principal": principal_arn,
                "last_used_days_ago": unused_days,
                "never_used": never_used,
                "reach_count": reach["count"],
            },
            f"Deactivate then delete access key {fingerprint} on {principal_arn} "
            "if no longer needed.",
        ))

    # Over-privileged: destructive/admin power on wildcard or prod resources.
    if reach["admin_wildcard"] or (reach["destructive"] and reach["hits_prod_or_wildcard"]):
        sev = "critical" if reach["admin_wildcard"] else "high"
        out.append(Finding(
            "over_privileged",
            f"aws:overpriv:{fingerprint}",
            sev,
            cred_id,
            {
                "fingerprint": fingerprint,
                "principal": principal_arn,
                "admin_wildcard": reach["admin_wildcard"],
                "destructive_actions": reach["destructive_actions"][:20],
                "reachable_resources": reach["resources"][:20],
                "reach_count": reach["count"],
            },
            "Scope this credential to only the actions and resources it uses "
            "(least privilege); remove wildcard/destructive grants.",
        ))

    # Stale authorization: key not rotated in >90d.
    if created is not None and (now - created).days > STALE_ROTATION_DAYS:
        out.append(Finding(
            "stale_authorization",
            f"aws:stale:{fingerprint}",
            "medium",
            cred_id,
            {"fingerprint": fingerprint, "principal": principal_arn,
             "age_days": (now - created).days},
            f"Rotate access key {fingerprint}; it is over "
            f"{STALE_ROTATION_DAYS} days old.",
        ))

    # Blast radius: always emitted as an informational map of reach.
    out.append(Finding(
        "blast_radius",
        f"aws:blast:{fingerprint}",
        "info",
        cred_id,
        {"fingerprint": fingerprint, "principal": principal_arn,
         "reach_count": reach["count"], "resources": reach["resources"][:50]},
        "Review what this credential can reach if compromised.",
    ))
    return out


def _blast_radius(conn: psycopg.Connection, principal_id: str) -> dict[str, Any]:
    """All resources reachable via the principal's permissions, plus flags."""
    rows = conn.execute(
        "SELECT DISTINCT r.identifier, r.environment, prr.access, p.scope "
        "FROM permissions p "
        "JOIN permission_reaches_resource prr ON prr.permission_id = p.id "
        "JOIN resources r ON r.id = prr.resource_id "
        "WHERE p.principal_id = %s",
        (principal_id,),
    ).fetchall()

    resources = sorted({r[0] for r in rows})
    destructive_actions = sorted({r[3] for r in rows if r[2] in ("write", "admin")})
    # Admin-wildcard: broad power (action "*" or "svc:*") over everything ("*").
    admin_wildcard = any(
        (r[3] == "*" or r[3].endswith(":*")) and r[0] == "aws:*:*" for r in rows
    )
    hits_prod_or_wildcard = any(r[1] == "prod" or r[0] == "aws:*:*" for r in rows)
    return {
        "count": len(resources),
        "resources": resources,
        "destructive": bool(destructive_actions),
        "destructive_actions": destructive_actions,
        "admin_wildcard": admin_wildcard,
        "hits_prod_or_wildcard": hits_prod_or_wildcard,
        # Provider-neutral views used by the GitHub rules.
        "access_levels": sorted({r[2] for r in rows}),
        "scopes": sorted({r[3] for r in rows}),
    }


def _blast_radius_for_credential(
    conn: psycopg.Connection, credential_id: str
) -> dict[str, Any]:
    """Provider permissions attached to one credential, never its owner's peers."""
    rows = conn.execute(
        "SELECT DISTINCT r.identifier, r.environment, prr.access, p.scope "
        "FROM permissions p "
        "JOIN permission_reaches_resource prr ON prr.permission_id = p.id "
        "JOIN resources r ON r.id = prr.resource_id "
        "WHERE p.credential_id = %s",
        (credential_id,),
    ).fetchall()
    resources = sorted({r[0] for r in rows})
    destructive_actions = sorted({r[3] for r in rows if r[2] in ("write", "admin")})
    return {
        "count": len(resources),
        "resources": resources,
        "destructive": bool(destructive_actions),
        "destructive_actions": destructive_actions,
        "admin_wildcard": False,
        "hits_prod_or_wildcard": False,
        "access_levels": sorted({r[2] for r in rows}),
        "scopes": sorted({r[3] for r in rows}),
    }


def persist_findings(conn: psycopg.Connection, tenant_id: str, findings: list[Finding]) -> None:
    for f in findings:
        conn.execute(
            "INSERT INTO findings (tenant_id, finding_type, natural_key, severity, "
            "credential_id, evidence, remediation, last_seen) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, now()) "
            "ON CONFLICT (tenant_id, natural_key) DO UPDATE SET "
            "severity = EXCLUDED.severity, evidence = EXCLUDED.evidence, "
            "remediation = EXCLUDED.remediation, last_seen = now()",
            (
                tenant_id, f.finding_type, f.natural_key, f.severity, f.credential_id,
                Jsonb(f.evidence), f.remediation,
            ),
        )
    conn.commit()
