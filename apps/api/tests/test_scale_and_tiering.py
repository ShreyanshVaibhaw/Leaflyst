"""Scale behaviour: object-store backpressure, storage tiering, bounded verify.

Two invariants are under test, and both are about what happens when something
is already going wrong:

1. An overloaded object store must degrade RECORDING, not reject the batch.
   Rejecting inverts the product's failure mode: the agent's recorder would
   start erroring while the agent itself is healthy.

2. A tiered payload must stay immediately readable. An archive class is
   cheaper but turns a retained payload into one that exists on paper and
   cannot be produced on demand, which is worthless to a responder mid-incident
   and to an auditor verifying an evidence pack.
"""

from __future__ import annotations

import uuid

import pytest
from abx_api import tiering
from abx_api.chain import row_to_event, verify_chain
from abx_api.ingest import ingest_events
from abx_api.store import ch_client, get_payload, pg_pool
from abx_api.tiering import TierClassError, cold_storage_class, run_tiering
from abx_schemas import IngestEvent
from conftest import requires_stack


def an_event(session_id: str, payload: str | None = "sensitive body") -> IngestEvent:
    return IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "scale-agent",
        "session_id": session_id, "seq": 0, "ts": "2026-07-31T00:00:00.000Z",
        "source": "mcp_tap", "event_type": "mcp_request",
        "operation": {"name": "tools/call echo", "outcome": "success"},
        "resource_refs": [], "payload": payload,
    })


def session_events(tenant_id: str, session_id: str) -> list[dict]:
    rows = ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(t)s AND session_id=%(s)s ORDER BY chain_seq",
        parameters={"t": tenant_id, "s": session_id},
    ).named_results()
    return [row_to_event(dict(row)) for row in rows]


# -- object-store backpressure -------------------------------------------------

@requires_stack
def test_object_store_failure_degrades_to_metadata_only(tenant, monkeypatch) -> None:
    """The agent keeps working and the record stays trustworthy; only the
    retrievable body is lost."""
    tenant_id, _ = tenant

    def unavailable(*_args: object, **_kwargs: object) -> tuple[str, list[int]]:
        raise OSError("object store unavailable")

    monkeypatch.setattr("abx_api.ingest.put_payload_batch", unavailable)

    session_id = f"backpressure-{uuid.uuid4()}"
    result = ingest_events(tenant_id, [an_event(session_id)])

    # Accepted, not rejected.
    assert result.accepted == 1
    assert result.payloads_dropped_by_backpressure == 1

    events = session_events(tenant_id, session_id)
    assert len(events) == 1
    # No retrievable body...
    assert events[0]["payload_ref"] is None
    # ...but the digest still commits to the real redacted content, so the
    # record is degraded rather than falsified.
    assert events[0]["payload_digest"] != "0" * 64
    valid, divergent = verify_chain(events)
    assert valid and divergent is None


@requires_stack
def test_a_healthy_batch_reports_no_backpressure(tenant) -> None:
    tenant_id, _ = tenant
    session_id = f"healthy-{uuid.uuid4()}"
    result = ingest_events(tenant_id, [an_event(session_id)])
    assert result.payloads_dropped_by_backpressure == 0
    events = session_events(tenant_id, session_id)
    assert events[0]["payload_ref"] is not None
    assert get_payload(events[0]["payload_ref"]) == b"sensitive body"


@requires_stack
def test_payloadless_events_are_unaffected_by_backpressure(tenant, monkeypatch) -> None:
    tenant_id, _ = tenant
    monkeypatch.setattr(
        "abx_api.ingest.put_payload_batch",
        lambda *a, **k: (_ for _ in ()).throw(OSError("down")),
    )
    session_id = f"nopayload-{uuid.uuid4()}"
    result = ingest_events(tenant_id, [an_event(session_id, payload=None)])
    assert result.accepted == 1
    assert result.payloads_dropped_by_backpressure == 0


# -- storage tiering -----------------------------------------------------------

def test_archive_classes_are_refused(monkeypatch) -> None:
    """A retained payload that needs a restore before it can be read is not
    really retained for the purposes this product exists for."""
    for archive in ("GLACIER", "DEEP_ARCHIVE", "GLACIER_IR"):
        monkeypatch.setattr(
            "abx_api.tiering.settings",
            type("S", (), {"payload_cold_storage_class": archive})(),
        )
        with pytest.raises(TierClassError, match="immediately readable"):
            cold_storage_class()


def test_readable_cold_classes_are_accepted(monkeypatch) -> None:
    for readable in ("STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING"):
        monkeypatch.setattr(
            "abx_api.tiering.settings",
            type("S", (), {"payload_cold_storage_class": readable})(),
        )
        assert cold_storage_class() == readable


@requires_stack
def test_tiering_is_off_unless_a_tenant_opts_in(tenant) -> None:
    """Moving storage class is a cost decision a customer opts into, not
    something done to them."""
    tenant_id, _ = tenant
    ingest_events(tenant_id, [an_event(f"tier-off-{uuid.uuid4()}")])
    with pg_pool().connection() as conn:
        conn.execute(
            "UPDATE payload_batches SET created_at = now() - INTERVAL '400 days' "
            "WHERE tenant_id = %s", (tenant_id,),
        )
    result = run_tiering()
    assert result.transitioned == 0


def _enable_tiering(tenant_id: str, tier_days: int = 30, age_days: int = 90) -> None:
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "payload_tier_days) VALUES (%s,365,TRUE,%s) ON CONFLICT (tenant_id) "
            "DO UPDATE SET retention_days=365, payload_tier_days=EXCLUDED.payload_tier_days",
            (tenant_id, tier_days),
        )
        if age_days:
            conn.execute(
                "UPDATE payload_batches SET created_at = now() - make_interval(days => %s) "
                "WHERE tenant_id = %s",
                (age_days, tenant_id),
            )


class _CopyStub:
    """Stands in for copy_object only; everything else is the real client."""

    def __init__(self, real: object, log: list[dict]) -> None:
        self._real = real
        self._log = log

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)

    def copy_object(self, **kwargs: object) -> dict:
        self._log.append(kwargs)
        return {}


@requires_stack
def test_aged_batches_tier_and_stay_readable(tenant, monkeypatch) -> None:
    """The point of restricting to immediately-readable classes: replay and
    evidence export keep working after a transition.

    The transition call itself is stubbed because MinIO, which backs the dev
    stack, rejects the infrequent-access classes outright. Everything around
    it is exercised for real: selection by age, the bookkeeping, and that the
    payload still reads back byte-identical afterwards.
    """
    tenant_id, _ = tenant
    session_id = f"tier-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)])
    payload_ref = session_events(tenant_id, session_id)[0]["payload_ref"]
    assert get_payload(payload_ref) == b"sensitive body"
    _enable_tiering(tenant_id)

    copied: list[dict] = []
    real_client = tiering.s3_client()
    monkeypatch.setattr("abx_api.tiering.s3_client", lambda: _CopyStub(real_client, copied))

    result = run_tiering()
    assert result.transitioned >= 1
    assert result.failed == 0
    assert copied[0]["StorageClass"] == "STANDARD_IA"
    # Same key, so segment byte offsets stay valid.
    assert copied[0]["CopySource"]["Key"] == copied[0]["Key"]

    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT storage_class, tiered_at FROM payload_batches WHERE tenant_id=%s "
            "ORDER BY created_at DESC LIMIT 1", (tenant_id,),
        ).fetchone()
    assert row is not None and str(row[0]) == "STANDARD_IA" and row[1] is not None

    # Still directly readable, and byte-identical.
    assert get_payload(payload_ref) == b"sensitive body"


@requires_stack
def test_a_store_that_refuses_the_class_is_reported_not_silent(tenant) -> None:
    """MinIO rejects infrequent-access classes. A tiering job that quietly does
    nothing is indistinguishable from one that works, and the bill would be the
    only thing that ever noticed - so the refusal has to be counted."""
    tenant_id, _ = tenant
    session_id = f"refused-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)])
    _enable_tiering(tenant_id)

    result = run_tiering()
    assert result.failed >= 1
    assert result.transitioned == 0

    # The payload is untouched: only the saving was lost.
    payload_ref = session_events(tenant_id, session_id)[0]["payload_ref"]
    assert get_payload(payload_ref) == b"sensitive body"
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT storage_class, tiered_at FROM payload_batches WHERE tenant_id=%s "
            "ORDER BY created_at DESC LIMIT 1", (tenant_id,),
        ).fetchone()
    assert row is not None and str(row[0]) == "STANDARD" and row[1] is None


@requires_stack
def test_recent_batches_stay_hot(tenant) -> None:
    tenant_id, _ = tenant
    ingest_events(tenant_id, [an_event(f"hot-{uuid.uuid4()}")])
    _enable_tiering(tenant_id, age_days=0)
    result = run_tiering()
    assert result.skipped_recent >= 1


@requires_stack
def test_tiering_never_reruns_the_same_batch(tenant, monkeypatch) -> None:
    tenant_id, _ = tenant
    ingest_events(tenant_id, [an_event(f"once-{uuid.uuid4()}")])
    _enable_tiering(tenant_id)
    stub = _CopyStub(tiering.s3_client(), [])  # resolve before patching the name
    monkeypatch.setattr("abx_api.tiering.s3_client", lambda: stub)
    first = run_tiering()
    second = run_tiering()
    assert first.transitioned >= 1
    assert second.transitioned == 0


@requires_stack
def test_tier_age_must_precede_retention(tenant) -> None:
    """Tiering after the payload is already deleted would be meaningless, so
    the database refuses the configuration outright."""
    import psycopg

    tenant_id, _ = tenant
    with pytest.raises(psycopg.errors.CheckViolation), pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "payload_tier_days) VALUES (%s,30,TRUE,90)",
            (tenant_id,),
        )


# -- bounded verification ------------------------------------------------------

@requires_stack
def test_verification_work_is_bounded_by_the_post_anchor_suffix(tenant) -> None:
    """Phase 10's anchor-prefix optimisation must still bound work as history
    grows, or verification cost rises with total history forever."""
    from abx_api.anchor import anchor_all
    from abx_api.verify import verify_tenant_chain

    tenant_id, _ = tenant
    for index in range(12):
        ingest_events(tenant_id, [an_event(f"hist-{index}-{uuid.uuid4()}")])
    anchor_all()
    anchored_head = 12

    for index in range(3):
        ingest_events(tenant_id, [an_event(f"tail-{index}-{uuid.uuid4()}")])

    result = verify_tenant_chain(tenant_id)
    assert result.valid
    # Only the post-anchor suffix plus the anchor checkpoint event is walked,
    # not all 15 events.
    assert result.events_checked < anchored_head + 3
