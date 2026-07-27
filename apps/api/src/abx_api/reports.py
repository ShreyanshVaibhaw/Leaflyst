"""Incident reports assembled from tenant-scoped forensic evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from abx_api.auth import require_admin
from abx_api.replay import GapMarker, SessionSummary, TimelineEvent, _load_session
from abx_api.settings import settings
from abx_api.store import pg_pool, s3_client
from abx_api.verify import VerifyResult

router = APIRouter(prefix="/v1/reports", dependencies=[Depends(require_admin)])


class ReportCredential(BaseModel):
    id: str | None
    provider: str
    kind: str
    fingerprint: str
    owner: str | None
    scopes: list[str] = Field(default_factory=list)
    reachable_resources: list[str] = Field(default_factory=list)


class ReportAlert(BaseModel):
    rule_id: str
    severity: str
    title: str
    event_id: str
    status: str
    last_seen: str


class ReportResource(BaseModel):
    provider: str
    kind: str
    resource_ref: str
    event_count: int
    credential_refs: list[str]


class ReportEvent(BaseModel):
    kind: str
    event_id: str | None = None
    seq: int | None = None
    ts: str | None = None
    operation: str | None = None
    target: str | None = None
    outcome: str | None = None
    duration_ms: int | None = None
    credential_ref: str | None = None
    missing_count: int | None = None


class IncidentReport(BaseModel):
    report_id: str
    generated_at: str
    summary: str
    session: SessionSummary
    credentials: list[ReportCredential]
    timeline: list[ReportEvent]
    blast_radius: list[ReportResource]
    alerts: list[ReportAlert]
    verification: VerifyResult
    chain_head_hash: str | None
    chain_head_seq: int | None
    anchor_ref: str | None
    anchor_status: str
    markdown: str


def _md(value: object | None) -> str:
    """Render untrusted text inside a Markdown table without enabling HTML."""
    if value is None:
        return "—"
    rendered = (
        str(value).replace("<", "&lt;").replace(">", "&gt;").replace("\r", " ").replace("\n", " ")
    )
    for marker in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|"):
        rendered = rendered.replace(marker, f"\\{marker}")
    return rendered


def build_report(tenant_id: str, session_id: str) -> IncidentReport:
    detail = _load_session(tenant_id, session_id)
    credential_refs = sorted(
        {
            item.credential_ref
            for item in detail.timeline
            if isinstance(item, TimelineEvent) and item.credential_ref
        }
    )
    credentials = _credentials(tenant_id, credential_refs)
    with pg_pool().connection() as conn:
        alert_rows = conn.execute(
            "SELECT rule_id, severity, title, event_id, status, last_seen FROM alerts "
            "WHERE tenant_id=%s AND session_id=%s ORDER BY last_seen",
            (tenant_id, session_id),
        ).fetchall()
        head = conn.execute(
            "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
    alerts = [
        ReportAlert(
            rule_id=row[0],
            severity=row[1],
            title=row[2],
            event_id=str(row[3]),
            status=row[4],
            last_seen=row[5].isoformat(),
        )
        for row in alert_rows
    ]
    timeline = [_report_event(item) for item in detail.timeline]
    resources = [
        ReportResource(
            provider=item.provider,
            kind=item.kind,
            resource_ref=item.resource_ref,
            event_count=len(item.event_ids),
            credential_refs=[credential.fingerprint for credential in item.credentials],
        )
        for item in detail.blast_radius
    ]
    generated = datetime.now(UTC).isoformat(timespec="milliseconds")
    summary = (
        f"Agent {detail.session.agent_id} performed {detail.session.event_count} recorded "
        f"actions and touched {len(resources)} distinct resources during this session. "
        f"{len(alerts)} anomaly alerts were associated with the activity."
    )
    head_hash = str(head[0]) if head else None
    head_seq = int(head[1]) if head else None
    anchor_ref, anchor_status = _latest_anchor(tenant_id, head_hash, head_seq)
    report = IncidentReport(
        report_id=f"ABX-{session_id}",
        generated_at=generated,
        summary=summary,
        session=detail.session,
        credentials=credentials,
        timeline=timeline,
        blast_radius=resources,
        alerts=alerts,
        verification=detail.verification,
        chain_head_hash=head_hash,
        chain_head_seq=head_seq,
        anchor_ref=anchor_ref,
        anchor_status=anchor_status,
        markdown="",
    )
    return report.model_copy(update={"markdown": render_markdown(report)})


def _credentials(tenant_id: str, fingerprints: list[str]) -> list[ReportCredential]:
    output: list[ReportCredential] = []
    with pg_pool().connection() as conn:
        for fingerprint in fingerprints:
            row = conn.execute(
                "SELECT c.id,c.provider,c.kind,c.fingerprint,p.external_id,c.owner_principal "
                "FROM credentials c LEFT JOIN principals p ON p.id=c.owner_principal "
                "WHERE c.tenant_id=%s AND c.fingerprint=%s",
                (tenant_id, fingerprint),
            ).fetchone()
            if row is None:
                output.append(
                    ReportCredential(
                        id=None,
                        provider="unknown",
                        kind="observed",
                        fingerprint=fingerprint,
                        owner=None,
                    )
                )
                continue
            permission_rows = conn.execute(
                "SELECT DISTINCT pm.scope,rs.identifier FROM permissions pm "
                "LEFT JOIN permission_reaches_resource pr ON pr.permission_id=pm.id "
                "LEFT JOIN resources rs ON rs.id=pr.resource_id "
                "WHERE pm.tenant_id=%s AND (pm.credential_id=%s OR pm.principal_id=%s)",
                (tenant_id, row[0], row[5]),
            ).fetchall()
            output.append(
                ReportCredential(
                    id=str(row[0]),
                    provider=row[1],
                    kind=row[2],
                    fingerprint=row[3],
                    owner=row[4],
                    scopes=sorted({value[0] for value in permission_rows}),
                    reachable_resources=sorted({value[1] for value in permission_rows if value[1]}),
                )
            )
    return output


def _report_event(item: TimelineEvent | GapMarker) -> ReportEvent:
    if isinstance(item, GapMarker):
        return ReportEvent(kind="gap", seq=item.before_seq, missing_count=item.missing_count)
    return ReportEvent(
        kind="event",
        event_id=item.event_id,
        seq=item.seq,
        ts=item.ts,
        operation=item.operation,
        target=item.target,
        outcome=item.outcome,
        duration_ms=item.duration_ms,
        credential_ref=item.credential_ref,
    )


def _latest_anchor(
    tenant_id: str, head_hash: str | None, head_seq: int | None
) -> tuple[str | None, str]:
    try:
        pages = s3_client().get_paginator("list_objects_v2").paginate(
            Bucket=settings.anchor_bucket, Prefix=f"{tenant_id}/"
        )
        keys = sorted(
            item["Key"] for page in pages for item in page.get("Contents", [])
        )
    except Exception:
        return None, "unavailable"
    if not keys:
        return None, "missing"
    ref = f"s3://{settings.anchor_bucket}/{keys[-1]}"
    try:
        body = s3_client().get_object(Bucket=settings.anchor_bucket, Key=keys[-1])["Body"].read()
        anchor = json.loads(body)
        anchor_hash = str(anchor["head_hash"])
        anchor_seq = int(anchor["head_seq"])
        if str(anchor["tenant_id"]) != tenant_id or head_seq is None or head_hash is None:
            return ref, "invalid"
        if anchor_seq == head_seq and anchor_hash == head_hash:
            return ref, "matched"
        if 0 <= anchor_seq < head_seq:
            return ref, "stale"
        return ref, "invalid"
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return ref, "invalid"
    except Exception:
        return ref, "unavailable"


def render_markdown(report: IncidentReport) -> str:
    valid = "VERIFIED" if report.verification.valid else "VERIFICATION FAILED"
    lines = [
        "# Leaflyst Incident Report",
        "",
        f"**Report ID:** {_md(report.report_id)}  ",
        f"**Generated:** {_md(report.generated_at)}  ",
        f"**Record integrity:** {valid}",
        "",
        "## Executive summary",
        "",
        _md(report.summary),
        "",
        "## Agent and session",
        "",
        f"- Agent: `{_md(report.session.agent_id)}`",
        f"- Session: `{_md(report.session.session_id)}`",
        f"- Window: {_md(report.session.started_at)} to {_md(report.session.ended_at)}",
        f"- Recorded events: {report.session.event_count}",
        "",
        "## Credentials",
        "",
        "| Provider | Kind | Fingerprint | Owner | Scanned scope |",
        "|---|---|---|---|---|",
    ]
    for credential in report.credentials:
        lines.append(
            f"| {_md(credential.provider)} | {_md(credential.kind)} | "
            f"`{_md(credential.fingerprint)}` | {_md(credential.owner)} | "
            f"{_md(', '.join(credential.scopes))} |"
        )
    lines.extend(
        [
            "",
            "## Timeline",
            "",
            "| Seq | Time | Operation | Target | Outcome | Credential |",
            "|---:|---|---|---|---|---|",
        ]
    )
    for event in report.timeline:
        if event.kind == "gap":
            lines.append(
                f"| {_md(event.seq)} | — | **RECORDING GAP** | "
                f"{event.missing_count} missing | — | — |"
            )
        else:
            lines.append(
                f"| {_md(event.seq)} | {_md(event.ts)} | {_md(event.operation)} | "
                f"{_md(event.target)} | {_md(event.outcome)} | "
                f"`{_md(event.credential_ref)}` |"
            )
    lines.extend(
        [
            "",
            "## Blast radius",
            "",
            "| Provider | Kind | Resource | Events | Credentials |",
            "|---|---|---|---:|---|",
        ]
    )
    for resource in report.blast_radius:
        lines.append(
            f"| {_md(resource.provider)} | {_md(resource.kind)} | "
            f"`{_md(resource.resource_ref)}` | {resource.event_count} | "
            f"{_md(', '.join(resource.credential_refs))} |"
        )
    lines.extend(["", "## Anomaly alerts", ""])
    if report.alerts:
        lines.extend(["| Severity | Rule | Alert | Status |", "|---|---|---|---|"])
        for alert in report.alerts:
            lines.append(
                f"| {_md(alert.severity)} | {_md(alert.rule_id)} | "
                f"{_md(alert.title)} | {_md(alert.status)} |"
            )
    else:
        lines.append("No anomaly alerts were associated with this session.")
    lines.extend(
        [
            "",
            "## Chain verification",
            "",
            f"- Result: **{valid}**",
            f"- Events checked: {report.verification.events_checked}",
            f"- Chain head: `{_md(report.chain_head_hash)}`",
            f"- Chain sequence: {_md(report.chain_head_seq)}",
            f"- Anchor: `{_md(report.anchor_ref or 'not yet anchored')}`",
            f"- Anchor status: **{_md(report.anchor_status)}**",
            "",
            "## Technical appendix",
            "",
            "| Seq | Event ID | Duration (ms) |",
            "|---:|---|---:|",
        ]
    )
    for event in report.timeline:
        if event.kind == "event":
            lines.append(
                f"| {_md(event.seq)} | `{_md(event.event_id)}` | {_md(event.duration_ms)} |"
            )
    return "\n".join(lines) + "\n"


@router.get("/sessions/{session_id}.md", response_class=PlainTextResponse)
def report_markdown(tenant_id: str, session_id: str) -> PlainTextResponse:
    return PlainTextResponse(
        build_report(tenant_id, session_id).markdown, media_type="text/markdown"
    )


@router.get("/sessions/{session_id}", response_model=IncidentReport)
def report_json(tenant_id: str, session_id: str) -> IncidentReport:
    return build_report(tenant_id, session_id)
