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
from datetime import UTC, datetime, timedelta

import pytest
from abx_api import tiering
from abx_api.chain import row_to_event, verify_chain
from abx_api.ingest import ingest_events
from abx_api.settings import settings
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


# -- tiering must not extend how long a payload is kept ------------------------

@requires_stack
def test_tiering_does_not_postpone_erasure(tenant, monkeypatch) -> None:
    """A retention promise is about when the payload was RECORDED.

    Tiering changes an object's storage class with a same-key copy, and a copy
    resets the object's LastModified. Retention used to expire by that
    timestamp, so tiering pushed the deadline out by exactly the tiering age: a
    tenant who asked for 30 days and tiered at 10 kept payloads for 40. The
    copy here is real, so the reset is real - only the storage class is stubbed,
    because MinIO rejects the infrequent-access family.
    """
    from abx_api.retention import run_retention
    from abx_api.store import s3_client

    tenant_id, _ = tenant
    session_id = f"erase-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)])

    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT object_key FROM payload_batches WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
    assert row is not None
    object_key = str(row[0])

    # Age the batch past a 30-day retention window, and tier it.
    _enable_tiering(tenant_id, tier_days=10, age_days=60)
    with pg_pool().connection() as conn:
        conn.execute(
            "UPDATE tenant_settings SET retention_days=30 WHERE tenant_id=%s", (tenant_id,)
        )

    real = s3_client()

    class _ClassStub:
        """Performs a REAL self-copy; only the refused class is swapped out."""

        def __getattr__(self, name: str) -> object:
            return getattr(real, name)

        def copy_object(self, **kwargs: object) -> dict:
            kwargs.pop("StorageClass", None)
            kwargs["MetadataDirective"] = "REPLACE"
            kwargs["Metadata"] = {"abx-tier": "cold"}
            return real.copy_object(**kwargs)

    monkeypatch.setattr("abx_api.tiering.s3_client", lambda: _ClassStub())
    assert run_tiering().transitioned >= 1

    # The object's own clock now reads "just now", which is the whole problem.
    touched = real.head_object(
        Bucket=settings.payload_bucket, Key=object_key
    )["LastModified"]
    assert touched > datetime.now(UTC) - timedelta(minutes=5), (
        "the copy did not reset LastModified, so this test cannot detect the bug"
    )

    assert run_retention() >= 1
    remaining = real.list_objects_v2(
        Bucket=settings.payload_bucket, Prefix=f"{tenant_id}/"
    ).get("Contents", [])
    assert not [o for o in remaining if o["Key"] == object_key], (
        "a tiered payload outlived the tenant's retention window"
    )

    # Erasure means the key is gone, not just the bytes.
    with pg_pool().connection() as conn:
        segments = conn.execute(
            "SELECT count(*) FROM payload_segments s JOIN payload_batches b "
            "ON b.id = s.batch_id WHERE b.tenant_id=%s", (tenant_id,)
        ).fetchone()
    assert segments is not None and int(segments[0]) == 0, (
        "the wrapped data keys survived the object they decrypt"
    )


@requires_stack
def test_retention_leaves_no_orphaned_keys_or_objects(tenant) -> None:
    """After erasure, nothing may point at something that is gone (SP-7).

    Two orphan directions, and only one of them is harmless.

    A payload object with no wrapped key left is fine - that is exactly what
    crypto-shredding produces, and the ciphertext is unreadable forever. A batch
    or segment row pointing at an object that no longer exists is NOT fine: the
    key survives its data, and replay follows that row into a 404 mid-incident,
    which is the moment a responder can least afford it.

    Both directions are checked, because asserting only "the object is gone"
    would pass with every key row still sitting in Postgres.
    """
    from abx_api.retention import run_retention
    from abx_api.store import s3_client

    tenant_id, _ = tenant
    session_id = f"orphan-{uuid.uuid4()}"
    ingest_events(tenant_id, [an_event(session_id)])

    with pg_pool().connection() as conn:
        before = conn.execute(
            "SELECT b.object_key, count(s.payload_ref) FROM payload_batches b "
            "LEFT JOIN payload_segments s ON s.batch_id = b.id "
            "WHERE b.tenant_id=%s GROUP BY b.object_key", (tenant_id,),
        ).fetchall()
    assert before and int(before[0][1]) >= 1, "no batch or key was written to erase"
    # Every object this tenant recorded, not just the first. Pinning one key
    # would let a second object survive retention while the test stayed green,
    # and the number of objects a batch produces is not this test's business to
    # assume.
    object_keys = {str(key) for key, _count in before}

    # Expire everything for this tenant.
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads) "
            "VALUES (%s,1,TRUE) ON CONFLICT (tenant_id) DO UPDATE SET retention_days=1",
            (tenant_id,),
        )
        conn.execute(
            "UPDATE payload_batches SET created_at = now() - interval '30 days' "
            "WHERE tenant_id=%s", (tenant_id,),
        )
    assert run_retention() >= 1

    remaining = s3_client().list_objects_v2(
        Bucket=settings.payload_bucket, Prefix=f"{tenant_id}/"
    ).get("Contents", [])
    live_objects = {str(item["Key"]) for item in remaining}
    survivors = object_keys & live_objects
    assert not survivors, f"payload bodies outlived their retention: {sorted(survivors)}"

    with pg_pool().connection() as conn:
        dangling_batches = conn.execute(
            "SELECT object_key FROM payload_batches WHERE tenant_id=%s", (tenant_id,)
        ).fetchall()
        dangling_keys = conn.execute(
            "SELECT count(*) FROM payload_segments s JOIN payload_batches b "
            "ON b.id = s.batch_id WHERE b.tenant_id=%s", (tenant_id,),
        ).fetchone()
    for (key,) in dangling_batches:
        assert str(key) in live_objects, f"a batch row points at a deleted object: {key}"
    assert dangling_keys is not None and int(dangling_keys[0]) == 0, (
        "wrapped data keys survived the objects they decrypt"
    )

    # And the events themselves are still there: retention deletes bodies, not
    # the record. A test that erased everything would pass the assertions above
    # while destroying the evidence they exist to protect.
    surviving = session_events(tenant_id, session_id)
    assert surviving, "retention removed the events, not just the payload bodies"
    valid, divergent = verify_chain(surviving)
    assert valid and divergent is None, "the chain broke when payloads were erased"
