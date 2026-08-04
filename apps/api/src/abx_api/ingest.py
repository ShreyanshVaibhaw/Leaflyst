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
from dataclasses import dataclass
from typing import Annotated, Any

import psycopg
from abx_schemas import IngestEvent
from abx_schemas.generated.contract import CURRENT_SCHEMA_VERSION
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from abx_api.auth import IngestIdentity, ingest_identity_from_token
from abx_api.chain import GENESIS_HASH, compute_event_hash, event_to_row, format_ts
from abx_api.metering import LimitState, decide_capture
from abx_api.payload_crypto import SealedPayload, seal
from abx_api.redaction import SECRET_RULES, redact, redact_and_truncate
from abx_api.settings import settings
from abx_api.store import (
    EVENT_COLUMNS,
    ch_client,
    payload_ref_for,
    pg_pool,
    put_payload_batch,
)

router = APIRouter()
logger = logging.getLogger(__name__)


class IngestBatch(BaseModel):
    events: Annotated[list[IngestEvent], Field(min_length=1, max_length=100_000)]


class IngestResult(BaseModel):
    accepted: int
    chain_head: str
    limit_state: LimitState
    over_limit_payload_events: int
    payloads_omitted_by_limit: int
    # Payloads dropped because the object store was unavailable. Reported so a
    # degraded batch is visibly degraded rather than silently thinner; the
    # events themselves were still accepted, chained, and verify.
    payloads_dropped_by_backpressure: int = 0


class BatchTooLargeError(ValueError):
    pass


@router.post("/v1/ingest", response_model=IngestResult)
def ingest(
    batch: IngestBatch,
    identity: Annotated[IngestIdentity, Depends(ingest_identity_from_token)],
) -> IngestResult:
    try:
        return ingest_events(
            identity.tenant_id,
            list(batch.events),
            ingest_token_id=identity.token_id,
            operator_ref=identity.operator_ref,
        )
    except BatchTooLargeError as exc:
        raise HTTPException(status_code=413, detail="batch too large") from exc


def ingest_events(
    tenant_id: str,
    events: list[IngestEvent],
    ingest_token_id: str | None = None,
    operator_ref: str | None = None,
) -> IngestResult:
    """Persist canonical events without depending on FastAPI transport models."""
    if not events:
        raise ValueError("at least one event is required")
    if len(events) > settings.max_batch_events:
        raise BatchTooLargeError

    with pg_pool().connection() as conn:
        # Coordinate capture/retention setting changes with in-flight batches.
        # The settings update locks the same tenant row through UPDATE, so once
        # it returns no batch that observed the old capture policy can still write.
        tenant = conn.execute(
            "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (tenant_id,)
        ).fetchone()
        assert tenant is not None
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
        tenant_setting = conn.execute(
            "SELECT capture_payloads FROM tenant_settings WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        capture_payloads = bool(tenant_setting[0]) if tenant_setting else True
        plan_row = conn.execute(
            "SELECT p.per_token_daily_payload_limit FROM tenants t "
            "LEFT JOIN tenant_plans p ON p.tenant_id=t.id "
            "WHERE t.id=%s",
            (tenant_id,),
        ).fetchone()
        assert plan_row is not None
        daily_event_limit = int(plan_row[0]) if plan_row[0] is not None else None
        current_captured_payloads = 0
        if ingest_token_id is not None:
            token_usage = conn.execute(
                "SELECT captured_payload_events FROM metering_token_daily "
                "WHERE tenant_id=%s AND token_id=%s AND day=CURRENT_DATE",
                (tenant_id, ingest_token_id),
            ).fetchone()
            current_captured_payloads = int(token_usage[0]) if token_usage else 0
        batch_payloads = sum(event.payload is not None for event in events)
        capture = decide_capture(
            current_captured_payloads,
            batch_payloads,
            daily_event_limit if ingest_token_id is not None and capture_payloads else None,
        )

        # Redact and seal every payload, write them as one object, then chain
        # sequentially over the results in order.
        prepared = prepare_events(
            tenant_id,
            events,
            capture_payloads,
            full_fidelity_payloads=capture.full_fidelity_payloads,
        )
        payloads_dropped_by_backpressure = write_payload_batch(conn, tenant_id, prepared)
        payloads_omitted_by_limit = capture.over_limit_payloads
        captured_payloads = sum(p.payload_ref is not None for p in prepared)
        rows: list[list[Any]] = []
        for p in prepared:
            event = finalize_event(
                tenant_id, p.event, prev_hash, p.digest, p.payload_ref,
                p.redactions, p.truncated, operator_ref,
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
        # Control-plane events are chained and verify like any other, but they
        # are OUR bookkeeping, not the tenant's recording. Metering them would
        # let issuing a token or changing a setting eat the tenant's plan
        # allowance and degrade their agent's payload capture as a side effect.
        metered = sum(1 for event in events if event.source.value != "admin_api")
        if metered:
            conn.execute(
                "INSERT INTO metering_daily (tenant_id, day, events) "
                "VALUES (%s, CURRENT_DATE, %s) ON CONFLICT (tenant_id, day) "
                "DO UPDATE SET events = metering_daily.events + %s",
                (tenant_id, metered, metered),
            )
        if ingest_token_id is not None and captured_payloads:
            conn.execute(
                "INSERT INTO metering_token_daily "
                "(tenant_id,token_id,day,captured_payload_events) "
                "VALUES (%s,%s,CURRENT_DATE,%s) ON CONFLICT (tenant_id,token_id,day) "
                "DO UPDATE SET captured_payload_events="
                "metering_token_daily.captured_payload_events+EXCLUDED.captured_payload_events",
                (tenant_id, ingest_token_id, captured_payloads),
            )

    try:
        from abx_rules.queue import enqueue_alerts

        enqueue_alerts(tenant_id, [str(event.event_id) for event in events])
    except Exception:
        logger.exception("anomaly evaluation degraded for tenant %s", tenant_id)
    return IngestResult(
        accepted=len(rows),
        chain_head=prev_hash,
        limit_state=capture.limit_state,
        over_limit_payload_events=capture.over_limit_payloads,
        payloads_omitted_by_limit=payloads_omitted_by_limit,
        payloads_dropped_by_backpressure=payloads_dropped_by_backpressure,
    )


@dataclass
class PreparedEvent:
    """An event after redaction, with its payload sealed but not yet stored."""

    event: IngestEvent
    digest: str
    payload_ref: str | None
    redactions: list[str]
    truncated: bool
    sealed: SealedPayload | None = None


def _scrub_credential_ref(ie: IngestEvent) -> tuple[IngestEvent, list[str]]:
    """Enforce the contract the schema only states.

    credential_ref is documented as "a fingerprint reference into the identity
    graph; never a secret value", but the agent supplies it and the recording
    plane does not depend on the agent's honesty. Unscrubbed, an agent that puts
    a real key here - maliciously, or by passing the wrong variable - gets it
    stored in ClickHouse in cleartext, echoed into the replay timeline and the
    incident report, and carried into evidence exports.

    Identifier rules are deliberately excluded. An AWS access key id is the
    public half of the pair, and the scanner stores it verbatim as
    credentials.fingerprint - scrubbing it here would break the join that links
    a replayed event to the credential it used, while protecting nothing. What
    is scrubbed is material that is actually secret: secret keys, tokens, JWTs,
    private keys, and passwords.

    The redacted form keeps the last four characters, which is exactly what a
    fingerprint is for, so the field still correlates events to one credential.
    """
    if not ie.credential_ref:
        return ie, []
    scrubbed, fired = redact(ie.credential_ref, SECRET_RULES)
    if not fired:
        return ie, []
    return ie.model_copy(update={"credential_ref": scrubbed}), fired


def _prepare_one(tenant_id: str, ie: IngestEvent, capture_payloads: bool) -> PreparedEvent:
    """Redact -> truncate -> digest -> seal.

    Deliberately performs no object-store call: every payload in the request is
    written together afterwards as a single object.
    """
    # Before the early return below and before the event is hashed, so an event
    # carrying no payload at all is still scrubbed, and the chain commits to the
    # value that was actually stored.
    ie, ref_redactions = _scrub_credential_ref(ie)
    if ie.payload is None:
        return PreparedEvent(ie, hashlib.sha256(b"").hexdigest(), None, ref_redactions, False)
    body, payload_redactions, truncated = redact_and_truncate(
        ie.payload, settings.payload_max_bytes
    )
    redactions = list(dict.fromkeys(ref_redactions + payload_redactions))
    # The digest covers the redacted plaintext, so the chain still commits to
    # real content and offline verification is unaffected by encryption at rest.
    digest = hashlib.sha256(body).hexdigest()
    if not capture_payloads:
        return PreparedEvent(ie, digest, None, redactions, truncated)
    return PreparedEvent(
        ie,
        digest,
        payload_ref_for(tenant_id, str(ie.event_id)),
        redactions,
        truncated,
        seal(body),
    )


def prepare_events(
    tenant_id: str,
    events: list[IngestEvent],
    capture_payloads: bool = True,
    full_fidelity_payloads: int | None = None,
) -> list[PreparedEvent]:
    """Prepare all events, preserving order.

    Runs sequentially: with the per-payload object write moved out, what remains
    is CPU-bound work under the GIL, where a thread pool only adds overhead.
    """
    capture_slots = len(events) if full_fidelity_payloads is None else full_fidelity_payloads
    prepared: list[PreparedEvent] = []
    for event in events:
        should_capture = capture_payloads and event.payload is not None and capture_slots > 0
        if should_capture:
            capture_slots -= 1
        prepared.append(_prepare_one(tenant_id, event, should_capture))
    return prepared


def write_payload_batch(
    conn: psycopg.Connection, tenant_id: str, prepared: list[PreparedEvent]
) -> int:
    """Write every sealed payload in the request as one object.

    One request instead of one per payload: the per-payload write was ~94% of
    ingest time. Each payload's location and wrapped key are recorded so it can
    be read back by byte range and erased individually.

    The object is written before the caller's transaction commits, so a crash
    can only leave an unreferenced object - which retention sweeps - never a
    segment row pointing at bytes that were never stored.
    """
    sealed = [(p, p.sealed) for p in prepared if p.sealed is not None]
    if not sealed:
        return 0
    try:
        object_key, offsets = put_payload_batch(tenant_id, [s.ciphertext for _, s in sealed])
    except Exception:
        # Object-store backpressure. Rejecting the batch would invert the
        # product's failure mode - the agent's recorder would start erroring
        # while the agent itself is healthy. Instead the batch degrades to
        # metadata-only: events still redact, digest, chain, and verify, and
        # payload_digest still commits to real content, so the record stays
        # trustworthy and only the retrievable body is lost.
        logger.exception("payload object store unavailable for tenant %s", tenant_id)
        for prepared_event, _ in sealed:
            prepared_event.payload_ref = None
            prepared_event.sealed = None
        return len(sealed)
    row = conn.execute(
        "INSERT INTO payload_batches (tenant_id, object_key, byte_size) "
        "VALUES (%s,%s,%s) RETURNING id",
        (tenant_id, object_key, sum(len(s.ciphertext) for _, s in sealed)),
    ).fetchone()
    assert row is not None
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO payload_segments (payload_ref, tenant_id, batch_id, byte_offset,"
            " byte_length, wrapped_key, key_nonce, data_nonce, master_key_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            [
                (
                    prepared_event.payload_ref, tenant_id, row[0], offset,
                    len(s.ciphertext), s.wrapped_key, s.key_nonce, s.data_nonce,
                    s.master_key_id,
                )
                for (prepared_event, s), offset in zip(sealed, offsets, strict=True)
            ],
        )
    return 0


def finalize_event(
    tenant_id: str,
    ie: IngestEvent,
    prev_hash: str,
    digest: str,
    payload_ref: str | None,
    redactions: list[str],
    truncated: bool,
    operator_ref: str | None = None,
) -> dict[str, Any]:
    """Assemble the canonical event and compute its hash (sequential, per-chain).

    Written at CURRENT_SCHEMA_VERSION. operator_ref comes from the ingest token,
    never from the producer body: an agent must not be able to name the human
    it is recorded against.
    """
    event: dict[str, Any] = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "operator_ref": operator_ref,
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
