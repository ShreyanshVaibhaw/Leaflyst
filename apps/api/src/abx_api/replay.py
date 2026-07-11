"""Tenant-scoped forensic replay, blast radius, and read-only sharing."""

from __future__ import annotations

import csv
import hashlib
import io
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from abx_api.auth import require_admin
from abx_api.store import ch_client, get_payload, pg_pool
from abx_api.verify import VerifyResult, verify_tenant_chain

router = APIRouter(prefix="/v1/replay")
admin = [Depends(require_admin)]


class CredentialLink(BaseModel):
    id: str
    provider: str
    kind: str
    fingerprint: str


class SessionSummary(BaseModel):
    session_id: str
    agent_id: str
    started_at: str
    ended_at: str
    event_count: int
    error_count: int


class AgentSummary(BaseModel):
    agent_id: str
    framework: str = ""
    status: str = "active"
    last_seen: str | None = None
    session_count: int = 0
    event_count: int = 0
    credentials: list[CredentialLink] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    kind: Literal["event"] = "event"
    event_id: str
    session_id: str
    seq: int
    ts: str
    source: str
    event_type: str
    operation: str
    provider: str | None
    target: str | None
    outcome: str
    duration_ms: int | None
    credential: CredentialLink | None
    credential_ref: str | None
    resource_refs: list[str]
    payload: str | None
    payload_truncated: bool
    redactions: list[str]


class GapMarker(BaseModel):
    kind: Literal["gap"] = "gap"
    after_seq: int
    before_seq: int
    missing_count: int


class BlastResource(BaseModel):
    resource_ref: str
    provider: str
    kind: str
    event_ids: list[str]
    credentials: list[CredentialLink]


class SessionDetail(BaseModel):
    session: SessionSummary
    timeline: list[TimelineEvent | GapMarker]
    blast_radius: list[BlastResource]
    verification: VerifyResult
    read_only: bool = False


class ShareRequest(BaseModel):
    expires_in_hours: int = Field(default=72, ge=1, le=24 * 30)


class ShareCreated(BaseModel):
    token: str
    share_path: str
    expires_at: str


def _query(sql: str, params: dict[str, object]) -> list[dict[str, Any]]:
    result = ch_client().query(sql, parameters=params)
    return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return cast(str, value.isoformat())
    return str(value)


def _credential_map(tenant_id: str, fingerprints: set[str]) -> dict[str, CredentialLink]:
    if not fingerprints:
        return {}
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT id, provider, kind, fingerprint FROM credentials "
            "WHERE tenant_id = %s AND fingerprint = ANY(%s)",
            (tenant_id, list(fingerprints)),
        ).fetchall()
    return {
        row[3]: CredentialLink(
            id=str(row[0]), provider=row[1], kind=row[2], fingerprint=row[3]
        )
        for row in rows
    }


@router.get("/agents", response_model=list[AgentSummary], dependencies=admin)
def agents(tenant_id: str) -> list[AgentSummary]:
    traffic = _query(
        "SELECT agent_id, countDistinct(session_id) AS sessions, count() AS events, "
        "max(ts) AS last_seen FROM events WHERE tenant_id = %(tenant)s GROUP BY agent_id",
        {"tenant": tenant_id},
    )
    aggregate = {row["agent_id"]: row for row in traffic}
    with pg_pool().connection() as conn:
        graph_agents = conn.execute(
            "SELECT id, name, framework, status, last_seen FROM agents WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchall()
        held = conn.execute(
            "SELECT a.name, c.id, c.provider, c.kind, c.fingerprint FROM agents a "
            "JOIN agent_holds_credential ahc ON ahc.agent_id = a.id "
            "JOIN credentials c ON c.id = ahc.credential_id "
            "WHERE a.tenant_id = %s AND c.tenant_id = %s",
            (tenant_id, tenant_id),
        ).fetchall()
    graph = {row[1]: row for row in graph_agents}
    credentials: dict[str, list[CredentialLink]] = {}
    for name, cid, provider, kind, fingerprint in held:
        credentials.setdefault(name, []).append(CredentialLink(
            id=str(cid), provider=provider, kind=kind, fingerprint=fingerprint
        ))
    names = sorted(set(aggregate) | set(graph))
    output: list[AgentSummary] = []
    for name in names:
        event = aggregate.get(name, {})
        node = graph.get(name)
        last_seen = event.get("last_seen") or (node[4] if node else None)
        output.append(AgentSummary(
            agent_id=name,
            framework=node[2] if node else "",
            status=node[3] if node else "active",
            last_seen=_iso(last_seen) if last_seen else None,
            session_count=int(event.get("sessions", 0)),
            event_count=int(event.get("events", 0)),
            credentials=credentials.get(name, []),
        ))
    return output


@router.get("/agents/{agent_id}/sessions", response_model=list[SessionSummary], dependencies=admin)
def agent_sessions(tenant_id: str, agent_id: str) -> list[SessionSummary]:
    rows = _query(
        "SELECT session_id, any(agent_id) AS agent_id, min(ts) AS started_at, "
        "max(ts) AS ended_at, count() AS event_count, countIf(op_outcome = 'error') AS errors "
        "FROM events WHERE tenant_id = %(tenant)s AND agent_id = %(agent)s "
        "GROUP BY session_id ORDER BY started_at DESC",
        {"tenant": tenant_id, "agent": agent_id},
    )
    return [_session_summary(row) for row in rows]


def _session_summary(row: dict[str, Any]) -> SessionSummary:
    return SessionSummary(
        session_id=row["session_id"], agent_id=row["agent_id"],
        started_at=_iso(row["started_at"]), ended_at=_iso(row["ended_at"]),
        event_count=int(row["event_count"]), error_count=int(row["errors"]),
    )


def _resource_kind(resource_ref: str) -> tuple[str, str]:
    parts = resource_ref.split(":", 2)
    if len(parts) >= 2 and parts[0] in {"aws", "github", "gh", "gcp", "azure"}:
        return ("github" if parts[0] == "gh" else parts[0], parts[1])
    if resource_ref.startswith(("http://", "https://")):
        return "web", "endpoint"
    if resource_ref.startswith("file:"):
        return "local", "file"
    return "other", parts[0] or "resource"


def _load_session(tenant_id: str, session_id: str, *, read_only: bool = False) -> SessionDetail:
    rows = _query(
        "SELECT * FROM events WHERE tenant_id = %(tenant)s AND session_id = %(session)s "
        "ORDER BY seq, ts, chain_seq",
        {"tenant": tenant_id, "session": session_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="session not found")
    credential_refs = {str(row["credential_ref"]) for row in rows if row["credential_ref"]}
    credentials = _credential_map(tenant_id, credential_refs)
    timeline: list[TimelineEvent | GapMarker] = []
    prior_seq: int | None = None
    resource_events: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        seq = int(row["seq"])
        if prior_seq is not None and seq > prior_seq + 1:
            timeline.append(GapMarker(
                after_seq=prior_seq, before_seq=seq, missing_count=seq - prior_seq - 1
            ))
        prior_seq = seq
        payload_ref = str(row["payload_ref"] or "")
        payload: str | None = None
        if payload_ref and payload_ref.startswith(f"{tenant_id}/"):
            body = get_payload(payload_ref)
            payload = body.decode("utf-8", errors="replace") if body is not None else None
        credential_ref = str(row["credential_ref"]) if row["credential_ref"] else None
        event = TimelineEvent(
            event_id=str(row["event_id"]), session_id=session_id,
            seq=seq, ts=_iso(row["ts"]),
            source=row["source"], event_type=row["event_type"], operation=row["op_name"],
            provider=row["op_provider"] or None, target=row["op_target"] or None,
            outcome=row["op_outcome"], duration_ms=row["op_duration_ms"],
            credential=credentials.get(credential_ref or ""), credential_ref=credential_ref,
            resource_refs=list(row["resource_refs"]), payload=payload,
            payload_truncated=bool(row["payload_truncated"]),
            redactions=list(row["redactions"]),
        )
        timeline.append(event)
        for resource_ref in event.resource_refs:
            resource_events.setdefault(resource_ref, []).append(row)
    blast: list[BlastResource] = []
    for resource_ref, touching in sorted(resource_events.items()):
        provider, kind = _resource_kind(resource_ref)
        refs = {str(row["credential_ref"]) for row in touching if row["credential_ref"]}
        blast.append(BlastResource(
            resource_ref=resource_ref, provider=provider, kind=kind,
            event_ids=[str(row["event_id"]) for row in touching],
            credentials=[credentials[ref] for ref in sorted(refs) if ref in credentials],
        ))
    first, last = rows[0], rows[-1]
    summary = SessionSummary(
        session_id=session_id, agent_id=first["agent_id"], started_at=_iso(first["ts"]),
        ended_at=_iso(last["ts"]), event_count=len(rows),
        error_count=sum(row["op_outcome"] == "error" for row in rows),
    )
    verification = verify_tenant_chain(tenant_id)
    if read_only and verification.first_divergent_event_id is not None:
        verification = verification.model_copy(update={"first_divergent_event_id": None})
    return SessionDetail(
        session=summary, timeline=timeline, blast_radius=blast,
        verification=verification, read_only=read_only,
    )


@router.get("/sessions/{session_id}", response_model=SessionDetail, dependencies=admin)
def session_detail(tenant_id: str, session_id: str) -> SessionDetail:
    return _load_session(tenant_id, session_id)


@router.get(
    "/credentials/{credential_id}/events",
    response_model=list[TimelineEvent],
    dependencies=admin,
)
def credential_events(tenant_id: str, credential_id: str) -> list[TimelineEvent]:
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT fingerprint FROM credentials WHERE tenant_id = %s AND id = %s",
            (tenant_id, credential_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="credential not found")
    records = _query(
        "SELECT session_id FROM events WHERE tenant_id = %(tenant)s "
        "AND credential_ref = %(fingerprint)s GROUP BY session_id ORDER BY max(ts) DESC",
        {"tenant": tenant_id, "fingerprint": row[0]},
    )
    events: list[TimelineEvent] = []
    for record in records:
        detail = _load_session(tenant_id, record["session_id"])
        events.extend(item for item in detail.timeline if isinstance(item, TimelineEvent)
                      and item.credential_ref == row[0])
    return events


@router.post("/sessions/{session_id}/share", response_model=ShareCreated, dependencies=admin)
def create_share(
    tenant_id: str, session_id: str, request: ShareRequest
) -> ShareCreated:
    _load_session(tenant_id, session_id)
    token = "abx_share_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.now(UTC) + timedelta(hours=request.expires_in_hours)
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO session_shares (tenant_id, session_id, token_hash, expires_at) "
            "VALUES (%s, %s, %s, %s)",
            (tenant_id, session_id, token_hash, expires_at),
        )
    return ShareCreated(
        token=token, share_path=f"/share/{token}", expires_at=expires_at.isoformat()
    )


@router.get("/shared/{token}", response_model=SessionDetail)
def shared_session(token: str) -> SessionDetail:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT tenant_id, session_id FROM session_shares WHERE token_hash = %s "
            "AND revoked_at IS NULL AND expires_at > now()",
            (token_hash,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="share not found or expired")
    return _load_session(str(row[0]), row[1], read_only=True)


@router.get(
    "/sessions/{session_id}/blast-radius.csv",
    response_class=PlainTextResponse,
    dependencies=admin,
)
def blast_radius_csv(tenant_id: str, session_id: str) -> PlainTextResponse:
    detail = _load_session(tenant_id, session_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["provider", "kind", "resource_ref", "event_ids", "credentials"])
    for resource in detail.blast_radius:
        writer.writerow([
            resource.provider, resource.kind, resource.resource_ref,
            " ".join(resource.event_ids),
            " ".join(credential.fingerprint for credential in resource.credentials),
        ])
    return PlainTextResponse(output.getvalue(), media_type="text/csv")


@router.get(
    "/sessions/{session_id}/blast-radius.json",
    response_model=list[BlastResource],
    dependencies=admin,
)
def blast_radius_json(tenant_id: str, session_id: str) -> list[BlastResource]:
    return _load_session(tenant_id, session_id).blast_radius
