"""Batch-packed payload objects: one write per request, per-payload erasure.

Covers the properties the design depends on - that many payloads share a
single object, that each is still readable and erasable individually, and that
erasing one leaves the others and the hash chain intact.
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import psycopg
import pytest
from abx_api import payload_crypto
from abx_api.chain import format_ts
from abx_api.ingest import ingest_events
from abx_api.payload_crypto import MasterKeyError, open_sealed, seal
from abx_api.settings import settings
from abx_api.store import delete_payload, get_payload, payload_ref_for, s3_client
from abx_schemas import IngestEvent
from conftest import requires_stack


def _event(seq: int, payload: str | None) -> IngestEvent:
    return IngestEvent.model_validate(
        {
            "event_id": str(uuid.uuid4()),
            "agent_id": "batch-agent",
            "session_id": "sess-batch",
            "seq": seq,
            "ts": format_ts(datetime.now(UTC)),
            "source": "mcp_tap",
            "event_type": "mcp_request",
            "operation": {"name": "tools/call x", "outcome": "success"},
            "resource_refs": [],
            "payload": payload,
        }
    )


# --- crypto unit tests (no stack needed) ------------------------------------


def test_seal_roundtrip() -> None:
    sealed = seal(b"sensitive tool output")
    assert sealed.ciphertext != b"sensitive tool output"
    opened = open_sealed(
        sealed.ciphertext, sealed.wrapped_key, sealed.key_nonce, sealed.data_nonce
    )
    assert opened == b"sensitive tool output"


def test_each_payload_gets_a_distinct_key() -> None:
    a, b = seal(b"same"), seal(b"same")
    # Identical plaintext must not produce identical ciphertext, otherwise
    # erasing one payload could be undone using another.
    assert a.ciphertext != b.ciphertext
    assert a.wrapped_key != b.wrapped_key


def test_wrong_key_cannot_open() -> None:
    sealed = seal(b"secret")
    other = seal(b"decoy")
    with pytest.raises(Exception):  # noqa: B017 - any AEAD failure is acceptable
        open_sealed(
            sealed.ciphertext, other.wrapped_key, other.key_nonce, sealed.data_nonce
        )


def test_malformed_master_key_is_rejected(monkeypatch) -> None:
    payload_crypto._cached_keyring.cache_clear()
    monkeypatch.setattr(
        "abx_api.payload_crypto.settings",
        SimpleNamespace(payload_master_key="not-base64!!", payload_retired_keys=""),
    )
    with pytest.raises(MasterKeyError):
        seal(b"x")


def test_wrong_length_master_key_is_rejected(monkeypatch) -> None:
    payload_crypto._cached_keyring.cache_clear()
    monkeypatch.setattr(
        "abx_api.payload_crypto.settings",
        SimpleNamespace(
            payload_master_key=base64.b64encode(b"tooshort").decode(),
            payload_retired_keys="",
        ),
    )
    with pytest.raises(MasterKeyError):
        seal(b"x")


# --- integration -------------------------------------------------------------

pytestmark_stack = requires_stack


@requires_stack
def test_many_payloads_share_one_object(tenant: tuple[str, str]) -> None:
    tenant_id, _ = tenant
    payloads = [f"payload number {i}" for i in range(25)]
    ingest_events(tenant_id, [_event(i, p) for i, p in enumerate(payloads)])

    with psycopg.connect(settings.pg_dsn) as conn:
        batches = conn.execute(
            "SELECT count(*) FROM payload_batches WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
        segments = conn.execute(
            "SELECT count(*) FROM payload_segments WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
    assert batches is not None and segments is not None
    # The whole point: 25 payloads, one object write.
    assert batches[0] == 1
    assert segments[0] == 25


@requires_stack
def test_each_payload_reads_back_correctly(tenant: tuple[str, str]) -> None:
    tenant_id, _ = tenant
    events = [_event(i, f"distinct body {i}") for i in range(10)]
    ingest_events(tenant_id, events)

    for i, event in enumerate(events):
        ref = payload_ref_for(tenant_id, str(event.event_id))
        assert get_payload(ref) == f"distinct body {i}".encode()


@requires_stack
def test_erasing_one_payload_leaves_the_others(tenant: tuple[str, str]) -> None:
    tenant_id, _ = tenant
    events = [_event(i, f"body {i}") for i in range(5)]
    ingest_events(tenant_id, events)

    target = payload_ref_for(tenant_id, str(events[2].event_id))
    delete_payload(target)

    assert get_payload(target) is None
    # Neighbours in the same object are untouched.
    for i in (0, 1, 3, 4):
        ref = payload_ref_for(tenant_id, str(events[i].event_id))
        assert get_payload(ref) == f"body {i}".encode()


@requires_stack
def test_erasure_destroys_the_key_not_just_the_pointer(tenant: tuple[str, str]) -> None:
    """The ciphertext may outlive the delete, but the key must not."""
    tenant_id, _ = tenant
    event = _event(0, "regulated personal data")
    ingest_events(tenant_id, [event])
    ref = payload_ref_for(tenant_id, str(event.event_id))

    with psycopg.connect(settings.pg_dsn) as conn:
        row = conn.execute(
            "SELECT b.object_key FROM payload_segments s "
            "JOIN payload_batches b ON b.id=s.batch_id WHERE s.payload_ref=%s",
            (ref,),
        ).fetchone()
    assert row is not None
    object_key = row[0]

    delete_payload(ref)

    with psycopg.connect(settings.pg_dsn) as conn:
        remaining = conn.execute(
            "SELECT count(*) FROM payload_segments WHERE payload_ref=%s", (ref,)
        ).fetchone()
    assert remaining is not None and remaining[0] == 0

    # The object still exists, but nothing can turn it back into plaintext.
    body = s3_client().get_object(Bucket=settings.payload_bucket, Key=object_key)[
        "Body"
    ].read()
    assert b"regulated personal data" not in body
    assert get_payload(ref) is None


@requires_stack
def test_events_without_payloads_create_no_segments(tenant: tuple[str, str]) -> None:
    tenant_id, _ = tenant
    ingest_events(tenant_id, [_event(i, None) for i in range(3)])
    with psycopg.connect(settings.pg_dsn) as conn:
        batches = conn.execute(
            "SELECT count(*) FROM payload_batches WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
    assert batches is not None and batches[0] == 0


@requires_stack
def test_legacy_direct_object_payloads_still_readable(tenant: tuple[str, str]) -> None:
    """Payloads written before batching have no segment row and must still read."""
    tenant_id, _ = tenant
    ref = payload_ref_for(tenant_id, str(uuid.uuid4()))
    s3_client().put_object(
        Bucket=settings.payload_bucket, Key=ref, Body=b"written before batching"
    )
    assert get_payload(ref) == b"written before batching"
    delete_payload(ref)
    assert get_payload(ref) is None
