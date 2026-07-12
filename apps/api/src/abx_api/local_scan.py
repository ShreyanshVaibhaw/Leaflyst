"""Write-only endpoint for findings produced by the customer-hosted scanner."""

from __future__ import annotations

from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from abx_api.auth import tenant_from_scan_token
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/scans/local")


class LocalGrant(BaseModel):
    action: str = Field(max_length=512)
    resource: str = Field(max_length=1024)
    kind: str = Field(max_length=100)
    environment: Literal["prod", "staging", "dev", "unknown"] = "unknown"
    access: Literal["read", "write", "admin"]


class LocalEvidence(BaseModel):
    age_days: int | None = None
    never_used: bool | None = None
    reach_count: int = 0
    reachable_resources: list[Annotated[str, Field(max_length=1024)]] = Field(
        default_factory=list, max_length=100
    )
    destructive_actions: list[Annotated[str, Field(max_length=512)]] = Field(
        default_factory=list, max_length=100
    )
    grants: list[LocalGrant] = Field(default_factory=list, max_length=1000)


class LocalFinding(BaseModel):
    natural_key: str = Field(max_length=512)
    finding_type: Literal[
        "orphaned_credential", "over_privileged", "stale_authorization", "blast_radius"
    ]
    severity: Literal["critical", "high", "medium", "low", "info"]
    provider: Literal["aws"] = "aws"
    credential_kind: str = Field(default="access_key", max_length=100)
    fingerprint: str = Field(max_length=256)
    owner: str = Field(max_length=512)
    evidence: LocalEvidence
    remediation: str = Field(max_length=2000)


class LocalScanUpload(BaseModel):
    scope: str = Field(max_length=512)
    api_calls: int = Field(ge=0)
    findings: list[LocalFinding] = Field(max_length=1000)


@router.post("")
def upload_local_scan(
    upload: LocalScanUpload,
    tenant_id: Annotated[str, Depends(tenant_from_scan_token)],
) -> dict[str, int | str]:
    with pg_pool().connection() as conn:
        run = conn.execute(
            "INSERT INTO scan_runs (tenant_id, provider, scope, finished_at, api_calls, status) "
            "VALUES (%s, 'aws', %s, now(), %s, 'succeeded') RETURNING id",
            (tenant_id, f"local:{upload.scope}", upload.api_calls),
        ).fetchone()
        assert run is not None
        for finding in upload.findings:
            principal = conn.execute(
                "INSERT INTO principals (tenant_id, provider, kind, external_id) "
                "VALUES (%s, 'aws', 'iam_user', %s) "
                "ON CONFLICT (tenant_id, provider, external_id) DO UPDATE "
                "SET external_id=EXCLUDED.external_id RETURNING id",
                (tenant_id, finding.owner),
            ).fetchone()
            assert principal is not None
            credential = conn.execute(
                "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, "
                "owner_principal) VALUES (%s, 'aws', %s, %s, %s) "
                "ON CONFLICT (tenant_id, provider, fingerprint) DO UPDATE SET last_scanned=now() "
                "RETURNING id",
                (tenant_id, finding.credential_kind, finding.fingerprint, principal[0]),
            ).fetchone()
            assert credential is not None
            _materialize_reach(conn, tenant_id, credential[0], finding.evidence.grants)
            conn.execute(
                "INSERT INTO findings (tenant_id, finding_type, natural_key, severity, "
                "credential_id, evidence, remediation) VALUES (%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id, natural_key) DO UPDATE SET severity=EXCLUDED.severity, "
                "evidence=EXCLUDED.evidence, remediation=EXCLUDED.remediation, last_seen=now(), "
                "status='open'",
                (
                    tenant_id,
                    finding.finding_type,
                    finding.natural_key,
                    finding.severity,
                    credential[0],
                    Jsonb(
                        {
                            **finding.evidence.model_dump(),
                            "fingerprint": finding.fingerprint,
                            "owner": finding.owner,
                        }
                    ),
                    finding.remediation,
                ),
            )
    return {"scan_run_id": str(run[0]), "findings": len(upload.findings)}


def _materialize_reach(
    conn: psycopg.Connection[Any],
    tenant_id: str,
    credential_id: object,
    grants: list[LocalGrant],
) -> None:
    for grant in grants:
        permission = conn.execute(
            "SELECT id FROM permissions WHERE tenant_id=%s AND credential_id=%s "
            "AND provider='aws' AND scope=%s LIMIT 1",
            (tenant_id, credential_id, grant.action),
        ).fetchone()
        if permission is None:
            permission = conn.execute(
                "INSERT INTO permissions (tenant_id,credential_id,provider,scope,raw) "
                "VALUES (%s,%s,'aws',%s,%s) RETURNING id",
                (tenant_id, credential_id, grant.action, Jsonb({"local_scan": True})),
            ).fetchone()
        assert permission is not None
        resource = conn.execute(
            "INSERT INTO resources (tenant_id,provider,kind,identifier,environment) "
            "VALUES (%s,'aws',%s,%s,%s) ON CONFLICT (tenant_id,provider,identifier) "
            "DO UPDATE SET kind=EXCLUDED.kind,environment=EXCLUDED.environment RETURNING id",
            (tenant_id, grant.kind, grant.resource, grant.environment),
        ).fetchone()
        assert resource is not None
        conn.execute(
            "INSERT INTO permission_reaches_resource (permission_id,resource_id,access) "
            "VALUES (%s,%s,%s) ON CONFLICT (permission_id,resource_id) "
            "DO UPDATE SET access=EXCLUDED.access",
            (permission[0], resource[0], grant.access),
        )
