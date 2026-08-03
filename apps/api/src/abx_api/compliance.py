"""EU AI Act Article 12 evidence pack (blueprint2 14.2).

Packaging over shipped capability. The hard part - an append-only,
hash-chained, anchor-verifiable record - already exists. This module adds the
period scoping, the operator roster, the policy statement, and the clause
mapping that turn it into something an auditor can act on.

Two deliberate constraints:

1. Verification reuses `abx-verify` unchanged. No second verifier is written,
   ever, so there is exactly one thing an auditor has to trust.

2. Because `abx-verify` requires a chain contiguous from genesis, the streamed
   chain is the genesis-through-anchor PREFIX covering the period end, not a
   bare mid-chain slice. A slice would need its opening prev_hash attested
   separately, which means a second trust root. The manifest names the
   chain_seq range that falls inside the requested period, so a reader can see
   exactly which events the period covers without the pack having to weaken
   how it is verified.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from abx_api.compliance_standards import (
    AI_ACT_HIGH_RISK_APPLICATION_DATE,
    ARTICLE_12_MINIMUM_RETENTION_DAYS,
    DRAFT_STANDARDS,
    clause_mapping,
)
from abx_api.controls import collect as collect_controls
from abx_api.evidence import _latest_anchor
from abx_api.ingest import ingest_events
from abx_api.rbac import require_export
from abx_api.redaction import RULES
from abx_api.store import ch_client, pg_pool

router = APIRouter(prefix="/v1/compliance", dependencies=[Depends(require_export)])


class OperatorEntry(BaseModel):
    operator_ref: str | None
    user_ref: str | None
    events: int
    sessions: int
    # Set when operator_ref is null: why this activity has no named person.
    unattributed_reason: str | None = None


class CompliancePack(BaseModel):
    format: str
    tenant_id: str
    generated_at: str
    period: dict[str, str]
    chain: dict[str, Any]
    operator_roster: list[OperatorEntry]
    retention_policy: dict[str, Any]
    redaction_policy: dict[str, Any]
    anchor: dict[str, Any]
    verification: dict[str, Any]
    article_12_mapping: list[dict[str, str]]
    draft_standards: list[dict[str, str]]
    scope_note: str
    manifest_digest: str


UNATTRIBUTED_REASON = (
    "recorded with an ingest token minted before operator binding existed, or "
    "with no operator assigned at token creation"
)

SCOPE_NOTE = (
    "Leaflyst states which artifact answers each clause and how to verify it "
    "independently. Whether a system is high-risk under the AI Act, and "
    "whether its deployer is compliant, are determinations for the deployer "
    "and its assessor, not for a vendor."
)


@router.get("/controls")
def control_report() -> dict[str, Any]:
    """SOC 2 / ISO 42001 control evidence collected from live behaviour.

    Exercises the controls rather than reporting configuration: a check that
    reads settings back proves nothing an attacker could not also have changed.
    Not tenant-scoped - these are platform controls, so no tenant_id is taken
    and none is leaked.
    """
    return collect_controls()


@router.get("/pack", response_model=CompliancePack)
def compliance_pack(tenant_id: str, period_from: str, period_to: str) -> CompliancePack:
    """Manifest for an Article 12 evidence pack covering a date range."""
    start, end = _parse_period(period_from, period_to)

    anchor = _latest_anchor(tenant_id)
    if anchor is None:
        raise HTTPException(status_code=409, detail="immutable chain anchor is unavailable")

    with pg_pool().connection() as conn:
        head = conn.execute(
            "SELECT head_hash,head_seq FROM chain_heads WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
        if head is None or int(head[1]) < 1:
            raise HTTPException(status_code=404, detail="tenant chain is empty")
        policy = conn.execute(
            "SELECT retention_days,compliance_mode,retention_floor_days,updated_at "
            "FROM tenant_settings WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        operator_names: dict[str, str] = dict(
            conn.execute(
                "SELECT id::text,user_ref FROM operators WHERE tenant_id=%s", (tenant_id,)
            ).fetchall()
        )

    period_rows = ch_client().query(
        "SELECT operator_ref,count() AS events,uniqExact(session_id) AS sessions,"
        "min(chain_seq) AS first_seq,max(chain_seq) AS last_seq "
        "FROM events WHERE tenant_id=%(t)s AND ts>=%(start)s AND ts<%(end)s "
        "GROUP BY operator_ref ORDER BY events DESC",
        parameters={"t": tenant_id, "start": start, "end": end},
    ).result_rows

    roster = [
        OperatorEntry(
            operator_ref=row[0] or None,
            user_ref=operator_names.get(row[0]) if row[0] else None,
            events=int(row[1]),
            sessions=int(row[2]),
            unattributed_reason=None if row[0] else UNATTRIBUTED_REASON,
        )
        for row in period_rows
    ]
    period_events = sum(entry.events for entry in roster)
    seqs = [(int(row[3]), int(row[4])) for row in period_rows]
    chain = {
        "head_seq": int(head[1]),
        "exported_through_seq": int(anchor["head_seq"]),
        "period_events": period_events,
        "period_first_chain_seq": min((s for s, _ in seqs), default=None),
        "period_last_chain_seq": max((e for _, e in seqs), default=None),
        "attributed_events": sum(e.events for e in roster if e.operator_ref),
        "unattributed_events": sum(e.events for e in roster if not e.operator_ref),
    }

    retention_days, compliance_mode, floor, updated_at = policy or (30, False, 180, None)
    retention_policy = {
        "retention_days": int(retention_days),
        "compliance_mode": bool(compliance_mode),
        "retention_floor_days": int(floor),
        "meets_article_12_minimum": int(retention_days) >= ARTICLE_12_MINIMUM_RETENTION_DAYS,
        "article_12_minimum_days": ARTICLE_12_MINIMUM_RETENTION_DAYS,
        # Identifies which policy revision was in force. Chained via the
        # attestation below, so a later change cannot rewrite this claim.
        "policy_version": updated_at.isoformat() if updated_at else "default",
        "high_risk_application_date": AI_ACT_HIGH_RISK_APPLICATION_DATE,
    }

    body: dict[str, Any] = {
        "format": "abx-compliance-pack-v1",
        "tenant_id": tenant_id,
        "generated_at": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "chain": chain,
        "operator_roster": [entry.model_dump() for entry in roster],
        "retention_policy": retention_policy,
        "redaction_policy": {
            "rules_in_force": [rule.id for rule in RULES],
            "skippable": False,
            "note": (
                "Redaction runs server-side at ingest and cannot be disabled by "
                "a producer; rule ids that fired are recorded per event."
            ),
        },
        "anchor": anchor,
        "verification": {
            "verifier": "tools/abx_verify.py",
            "chain_export": f"GET /v1/evidence/tenant?tenant_id={tenant_id}",
            "command": "python abx_verify.py chain.ndjson --anchor-hash <anchor head_hash>",
            "anchor_hash": anchor["head_hash"],
            "note": (
                "The exported chain runs from genesis through the anchor so it "
                "verifies standalone. The period fields above name the portion "
                "inside the requested range."
            ),
        },
        "article_12_mapping": clause_mapping(),
        "draft_standards": [dict(entry) for entry in DRAFT_STANDARDS],
        "scope_note": SCOPE_NOTE,
    }
    body["manifest_digest"] = _digest(body)
    _record_attestation(tenant_id, body)
    return CompliancePack.model_validate(body)


def _digest(body: dict[str, Any]) -> str:
    """Digest over the manifest, excluding the digest field itself."""
    doc = {k: v for k, v in body.items() if k != "manifest_digest"}
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _record_attestation(tenant_id: str, body: dict[str, Any]) -> None:
    """Chain the fact that this pack was produced, and what it claimed.

    Without this the manifest is an unsigned assertion a vendor made about
    itself. Chained, the retention policy and operator roster asserted at
    generation time become as tamper-evident as the events they describe, so a
    later policy change cannot quietly rewrite what a past pack claimed.

    Generation must not fail because attestation failed; the pack is still
    verifiable from the chain and anchor on its own.
    """
    event = IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "abx-admin",
        "session_id": f"compliance-pack:{uuid.uuid4()}", "seq": 0,
        "ts": datetime.now(UTC), "source": "admin_api", "event_type": "agent_step",
        "operation": {
            "name": "compliance evidence pack generated", "provider": "leaflyst",
            "target": body["period"]["from"], "outcome": "success", "duration_ms": 0,
        },
        "resource_refs": [
            f"abx:compliance-pack:{body['manifest_digest']}",
            f"abx:retention-policy:{body['retention_policy']['policy_version']}",
        ],
        "payload": json.dumps({
            "period": body["period"],
            "retention_policy": body["retention_policy"],
            "chain": body["chain"],
            "manifest_digest": body["manifest_digest"],
        }, default=str),
    })
    try:
        ingest_events(tenant_id, [event])
    except Exception:
        return


def _parse_period(period_from: str, period_to: str) -> tuple[datetime, datetime]:
    try:
        start = datetime.fromisoformat(period_from)
        end = datetime.fromisoformat(period_to)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="period must be ISO-8601") from exc
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    if end <= start:
        raise HTTPException(status_code=422, detail="period_to must be after period_from")
    return start, end
