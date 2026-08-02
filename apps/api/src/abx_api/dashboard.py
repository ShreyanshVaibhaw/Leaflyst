"""Dashboard read API (blueprint 7). Every query is tenant-scoped.

Auth at MVP is the shared admin key plus an explicit tenant_id (dashboard
sessions gain per-tenant read tokens in a later phase). No ingest token is
ever accepted here - ingest tokens are write-only by construction.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from abx_api.export_safety import csv_cell
from abx_api.identifiers import ResourceId
from abx_api.rbac import require_read
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/dashboard", dependencies=[Depends(require_read)])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class Overview(BaseModel):
    tenant_id: str
    findings_by_severity: dict[str, int]
    open_findings: int
    credentials: int
    agents: int
    providers_scanned: list[str]
    scary_number: str


def _rows(sql: str, params: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    with pg_pool().connection() as conn:
        return conn.execute(sql, params).fetchall()


@router.get("/overview", response_model=Overview)
def overview(tenant_id: str) -> Overview:
    sev_rows = _rows(
        "SELECT severity, count(*) FROM findings "
        "WHERE tenant_id = %s AND status = 'open' AND finding_type <> 'blast_radius' "
        "GROUP BY severity",
        (tenant_id,),
    )
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for sev, n in sev_rows:
        by_sev[sev] = n
    creds = _rows("SELECT count(*) FROM credentials WHERE tenant_id = %s", (tenant_id,))[0][0]
    agents = _rows("SELECT count(*) FROM agents WHERE tenant_id = %s", (tenant_id,))[0][0]
    providers = [
        r[0] for r in _rows(
            "SELECT DISTINCT provider FROM scan_runs WHERE tenant_id = %s AND status='succeeded'",
            (tenant_id,),
        )
    ]
    open_total = sum(by_sev.values())
    orphaned = _rows(
        "SELECT count(*) FROM findings WHERE tenant_id = %s AND status='open' "
        "AND finding_type = 'orphaned_credential'",
        (tenant_id,),
    )[0][0]
    scary = (
        f"{orphaned} credential belongs to a dead or dormant agent"
        if orphaned == 1
        else f"{orphaned} credentials belong to dead or dormant agents"
    ) if orphaned else (
        f"{open_total} open findings across your agent credentials"
    )
    return Overview(
        tenant_id=tenant_id,
        findings_by_severity=by_sev,
        open_findings=open_total,
        credentials=creds,
        agents=agents,
        providers_scanned=providers,
        scary_number=scary,
    )


class FindingSummary(BaseModel):
    id: str
    finding_type: str
    severity: str
    provider: str | None
    fingerprint: str | None
    owner: str | None
    remediation: str


@router.get("/findings", response_model=list[FindingSummary])
def findings_list(
    tenant_id: str,
    severity: str | None = None,
    finding_type: str | None = None,
    provider: str | None = None,
) -> list[FindingSummary]:
    clauses = ["f.tenant_id = %s", "f.status = 'open'"]
    params: list[Any] = [tenant_id]
    if severity:
        clauses.append("severity = %s")
        params.append(severity)
    if finding_type:
        clauses.append("f.finding_type = %s")
        params.append(finding_type)
    if provider:
        clauses.append("c.provider = %s")
        params.append(provider)
    rows = _rows(
        "SELECT f.id, f.finding_type, f.severity, f.evidence, f.remediation, c.provider "
        "FROM findings f LEFT JOIN credentials c ON c.id = f.credential_id "
        f"WHERE {' AND '.join(clauses)} "  # noqa: S608 - clause list is static
        "ORDER BY array_position(%s::text[], f.severity), f.finding_type",
        (*params, SEVERITY_ORDER),
    )
    return [
        FindingSummary(
            id=str(r[0]),
            finding_type=r[1],
            severity=r[2],
            provider=r[5],
            fingerprint=(r[3] or {}).get("fingerprint"),
            owner=(r[3] or {}).get("principal") or (r[3] or {}).get("owner"),
            remediation=r[4],
        )
        for r in rows
    ]


class FindingDetail(FindingSummary):
    evidence: dict[str, Any]


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def finding_detail(tenant_id: str, finding_id: ResourceId) -> FindingDetail:
    rows = _rows(
        "SELECT f.id, f.finding_type, f.severity, f.evidence, f.remediation, c.provider "
        "FROM findings f LEFT JOIN credentials c ON c.id = f.credential_id "
        "WHERE f.tenant_id = %s AND f.id = %s",
        (tenant_id, finding_id),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="finding not found")
    r = rows[0]
    ev = r[3] or {}
    return FindingDetail(
        id=str(r[0]), finding_type=r[1], severity=r[2],
        provider=r[5],
        fingerprint=ev.get("fingerprint"),
        owner=ev.get("principal") or ev.get("owner"),
        remediation=r[4], evidence=ev,
    )


class CredentialSummary(BaseModel):
    id: str
    provider: str
    kind: str
    fingerprint: str
    owner: str | None
    last_used_at: str | None
    status: str
    open_findings: int


class PermissionReach(BaseModel):
    scope: str
    resource: str | None
    access: str | None


class CredentialDetail(CredentialSummary):
    created_at: str | None
    permissions: list[PermissionReach]
    findings: list[FindingSummary]


@router.get("/credentials", response_model=list[CredentialSummary])
def credentials_list(tenant_id: str) -> list[CredentialSummary]:
    rows = _rows(
        "SELECT c.id, c.provider, c.kind, c.fingerprint, p.external_id, "
        "c.last_used_at, c.status, "
        "(SELECT count(*) FROM findings f WHERE f.credential_id = c.id "
        " AND f.status='open' AND f.finding_type <> 'blast_radius') "
        "FROM credentials c LEFT JOIN principals p ON c.owner_principal = p.id "
        "WHERE c.tenant_id = %s ORDER BY c.provider, c.kind",
        (tenant_id,),
    )
    return [
        CredentialSummary(
            id=str(r[0]), provider=r[1], kind=r[2], fingerprint=r[3], owner=r[4],
            last_used_at=r[5].isoformat() if r[5] else None, status=r[6],
            open_findings=r[7],
        )
        for r in rows
    ]


@router.get("/credentials/{credential_id}", response_model=CredentialDetail)
def credential_detail(tenant_id: str, credential_id: ResourceId) -> CredentialDetail:
    rows = _rows(
        "SELECT c.id, c.provider, c.kind, c.fingerprint, p.external_id, "
        "c.last_used_at, c.status, c.created_at_provider, "
        "(SELECT count(*) FROM findings f WHERE f.credential_id = c.id "
        " AND f.status='open' AND f.finding_type <> 'blast_radius') "
        "FROM credentials c LEFT JOIN principals p ON c.owner_principal = p.id "
        "WHERE c.tenant_id = %s AND c.id = %s",
        (tenant_id, credential_id),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="credential not found")
    r = rows[0]
    reaches = _rows(
        "SELECT pm.scope, rs.identifier, pr.access FROM permissions pm "
        "LEFT JOIN permission_reaches_resource pr ON pr.permission_id = pm.id "
        "LEFT JOIN resources rs ON rs.id = pr.resource_id "
        "WHERE pm.tenant_id = %s AND (pm.credential_id = %s OR "
        "(pm.credential_id IS NULL AND pm.principal_id = "
        "(SELECT owner_principal FROM credentials WHERE tenant_id = %s AND id = %s)) "
        ") "
        "ORDER BY pm.scope, rs.identifier",
        (tenant_id, credential_id, tenant_id, credential_id),
    )
    finding_rows = _rows(
        "SELECT f.id, f.finding_type, f.severity, f.evidence, f.remediation, c.provider "
        "FROM findings f JOIN credentials c ON c.id = f.credential_id "
        "WHERE f.tenant_id = %s AND f.credential_id = %s AND f.status = 'open' "
        "AND f.finding_type <> 'blast_radius' "
        "ORDER BY array_position(%s::text[], f.severity), f.finding_type",
        (tenant_id, credential_id, SEVERITY_ORDER),
    )
    credential_findings = [
        FindingSummary(
            id=str(x[0]), finding_type=x[1], severity=x[2], provider=x[5],
            fingerprint=(x[3] or {}).get("fingerprint"),
            owner=(x[3] or {}).get("principal") or (x[3] or {}).get("owner"),
            remediation=x[4],
        )
        for x in finding_rows
    ]
    return CredentialDetail(
        id=str(r[0]), provider=r[1], kind=r[2], fingerprint=r[3], owner=r[4],
        last_used_at=r[5].isoformat() if r[5] else None, status=r[6],
        created_at=r[7].isoformat() if r[7] else None, open_findings=r[8],
        permissions=[PermissionReach(scope=x[0], resource=x[1], access=x[2]) for x in reaches],
        findings=credential_findings,
    )


class IntegrationStatus(BaseModel):
    provider: str
    connected: bool
    last_scan: str | None
    credentials_found: int
    account: str | None = None


@router.get("/integrations", response_model=list[IntegrationStatus])
def integrations(tenant_id: str) -> list[IntegrationStatus]:
    out: list[IntegrationStatus] = []
    for provider in ("aws", "github", "gcp"):
        connection = _rows(
            "SELECT account_login FROM integration_connections "
            "WHERE tenant_id = %s AND provider = %s AND status = 'connected' "
            "ORDER BY updated_at DESC LIMIT 1",
            (tenant_id, provider),
        )
        last = _rows(
            "SELECT max(finished_at) FROM scan_runs "
            "WHERE tenant_id = %s AND provider = %s AND status = 'succeeded'",
            (tenant_id, provider),
        )[0][0]
        count = _rows(
            "SELECT count(*) FROM credentials WHERE tenant_id = %s AND provider = %s",
            (tenant_id, provider),
        )[0][0]
        out.append(IntegrationStatus(
            provider=provider,
            connected=last is not None or bool(connection),
            last_scan=last.isoformat() if last else None,
            credentials_found=count,
            account=connection[0][0] if connection else None,
        ))
    return out


@router.get("/findings.csv", response_class=PlainTextResponse)
def findings_csv(tenant_id: str) -> PlainTextResponse:
    rows = _rows(
        "SELECT finding_type, severity, evidence->>'fingerprint', remediation FROM findings "
        "WHERE tenant_id = %s AND status='open' ORDER BY severity",
        (tenant_id,),
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["finding_type", "severity", "fingerprint", "remediation"])
    w.writerows([csv_cell(value) for value in row] for row in rows)
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")


@router.get("/findings.md", response_class=PlainTextResponse)
def findings_markdown(tenant_id: str) -> PlainTextResponse:
    rows = _rows(
        "SELECT finding_type, severity, evidence, remediation FROM findings "
        "WHERE tenant_id = %s AND status='open' AND finding_type <> 'blast_radius' "
        "ORDER BY array_position(%s::text[], severity)",
        (tenant_id, SEVERITY_ORDER),
    )
    lines = ["# Credential Findings", ""]
    for ftype, sev, ev, rem in rows:
        fp = (ev or {}).get("fingerprint", "")
        owner = (ev or {}).get("principal") or (ev or {}).get("owner", "")
        lines.append(f"## [{sev.upper()}] {ftype.replace('_', ' ')}")
        lines.append(f"- Credential: `{fp}` ({owner})")
        lines.append(f"- Remediation: {rem}")
        lines.append("")
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


class ExportJSON(BaseModel):
    tenant_id: str
    findings: list[dict[str, Any]]


@router.get("/findings.json", response_model=ExportJSON)
def findings_json(tenant_id: str) -> ExportJSON:
    rows = _rows(
        "SELECT finding_type, severity, evidence, remediation FROM findings "
        "WHERE tenant_id = %s AND status='open' ORDER BY severity",
        (tenant_id,),
    )
    return ExportJSON(
        tenant_id=tenant_id,
        findings=[
            {"finding_type": r[0], "severity": r[1], "evidence": r[2], "remediation": r[3]}
            for r in rows
        ],
    )
