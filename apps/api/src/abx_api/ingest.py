"""POST /v1/ingest - the collector (blueprint 4.1, 4.3).

Pipeline per batch, in fixed order:
  authenticate (write-only token -> tenant)
  -> redact (server-side, non-skippable) -> truncate -> digest
  -> payload body to object store
  -> hash-chain append (per-tenant, serialized on the chain head row)
  -> events to ClickHouse
  -> chain head checkpoint + metering commit

Concurrent batches for one tenant serialize on chain_heads via
SELECT ... FOR UPDATE; different tenants proceed in parallel.
"""

from __future__ import annotations

import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Annotated, Any

from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from abx_api.auth import tenant_from_token
from abx_api.chain import GENESIS_HASH, compute_event_hash, event_to_row, format_ts
from abx_api.redaction import redact_and_truncate
from abx_api.settings import settings
from abx_api.store import EVENT_COLUMNS, ch_client, pg_pool, put_payload

router = APIRouter()
logger = logging.getLogger(__name__)


class IngestBatch(BaseModel):
    events: Annotated[list[IngestEvent], Field(min_length=1, max_length=100_000)]


class IngestResult(BaseModel):
    accepted: int
    chain_head: str


@router.post("/v1/ingest", response_model=IngestResult)
def ingest(
    batch: IngestBatch, tenant_id: Annotated[str, Depends(tenant_from_token)]
) -> IngestResult:
    if len(batch.events) > settings.max_batch_events:
        raise HTTPException(status_code=413, detail="batch too large")

    with pg_pool().connection() as conn:
        # Serialize concurrent batches per tenant on the chain-head row.
        head = conn.execute(
            "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id = %s FOR UPDATE",
            (tenant_id,),
        ).fetchone()
        if head is None:
            conn.execute(
                "INSERT INTO chain_heads (tenant_id, head_hash, head_seq) VALUES (%s, %s, 0) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id, GENESIS_HASH),
            )
            head = conn.execute(
                "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id = %s FOR UPDATE",
                (tenant_id,),
            ).fetchone()
            assert head is not None
        prev_hash, chain_seq = str(head[0]), int(head[1])

        # Redact + store payloads concurrently (S3 puts are the per-event
        # bottleneck), then chain sequentially over the results in order.
        prepared = prepare_events(tenant_id, list(batch.events))
        rows: list[list[Any]] = []
        for ie, digest, payload_ref, redactions, truncated in prepared:
            event = finalize_event(
                tenant_id, ie, prev_hash, digest, payload_ref, redactions, truncated
            )
            chain_seq += 1
            rows.append(event_to_row(event, chain_seq))
            prev_hash = event["event_hash"]

        # ponytail: CH insert inside the PG transaction; a PG commit failure
        # after a successful CH insert leaves orphan rows that verification
        # will surface. Exactly-once needs idempotent replay keyed on event_id.
        ch_client().insert("events", rows, column_names=EVENT_COLUMNS)

        conn.execute(
            "UPDATE chain_heads SET head_hash = %s, head_seq = %s, updated_at = now() "
            "WHERE tenant_id = %s",
            (prev_hash, chain_seq, tenant_id),
        )
        conn.execute(
            "INSERT INTO metering_daily (tenant_id, day, events) VALUES (%s, CURRENT_DATE, %s) "
            "ON CONFLICT (tenant_id, day) DO UPDATE SET events = metering_daily.events + %s",
            (tenant_id, len(rows), len(rows)),
        )

    try:
        from abx_rules.worker import enqueue_alerts

        enqueue_alerts(tenant_id, [str(event.event_id) for event in batch.events])
    except Exception:
        logger.exception("anomaly evaluation degraded for tenant %s", tenant_id)
    return IngestResult(accepted=len(rows), chain_head=prev_hash)


# (event, digest, payload_ref, redactions, truncated)
_Prepared = tuple[IngestEvent, str, str | None, list[str], bool]


def _prepare_one(tenant_id: str, ie: IngestEvent) -> _Prepared:
    """Redact -> truncate -> digest -> store body. The parallelizable, side-effecting
    part; no chaining here (that must stay sequential)."""
    if ie.payload is None:
        return ie, hashlib.sha256(b"").hexdigest(), None, [], False
    body, redactions, truncated = redact_and_truncate(ie.payload, settings.payload_max_bytes)
    digest = hashlib.sha256(body).hexdigest()
    payload_ref = put_payload(tenant_id, str(ie.event_id), body)
    return ie, digest, payload_ref, redactions, truncated


def prepare_events(tenant_id: str, events: list[IngestEvent]) -> list[_Prepared]:
    """Prepare all events, preserving order. S3 puts run concurrently."""
    if not any(e.payload for e in events):
        return [_prepare_one(tenant_id, e) for e in events]
    with ThreadPoolExecutor(max_workers=16) as pool:
        return list(pool.map(lambda e: _prepare_one(tenant_id, e), events))


def finalize_event(
    tenant_id: str,
    ie: IngestEvent,
    prev_hash: str,
    digest: str,
    payload_ref: str | None,
    redactions: list[str],
    truncated: bool,
) -> dict[str, Any]:
    """Assemble the canonical event and compute its hash (sequential, per-chain)."""
    event: dict[str, Any] = {
        "event_id": str(ie.event_id),
        "tenant_id": tenant_id,
        "agent_id": ie.agent_id,
        "session_id": ie.session_id,
        "seq": ie.seq,
        "ts": format_ts(ie.ts),
        "source": ie.source.value,
        "event_type": ie.event_type.value,
        "operation": {
            "name": ie.operation.name,
            "provider": ie.operation.provider,
            "target": ie.operation.target,
            "outcome": ie.operation.outcome.value,
            "duration_ms": ie.operation.duration_ms,
        },
        "credential_ref": ie.credential_ref,
        "resource_refs": [r.root for r in ie.resource_refs],
        "payload_digest": digest,
        "payload_ref": payload_ref,
        "payload_truncated": truncated,
        "redactions": redactions,
        "prev_hash": prev_hash,
    }
    event["event_hash"] = compute_event_hash(event)
    return event
