"""Payload master-key lifecycle (blueprint2 13.3).

Before this, nothing recorded WHICH master key wrapped a given data key, so
rotating silently rendered every stored payload permanently unreadable with no
way to detect it beforehand. For a product whose erasure guarantee is "destroy
the key", that lifecycle is load-bearing infrastructure.

The drill these tests encode: promote a new key, confirm old payloads still
read, re-wrap, then confirm the old key can be dropped safely - and that
dropping it too early fails loudly instead of quietly.
"""

from __future__ import annotations

import base64
import uuid
from types import SimpleNamespace

import pytest
from abx_api import key_rotation, payload_crypto
from abx_api.payload_crypto import MasterKeyError, parse_keyring, seal
from abx_api.settings import Settings, production_config_errors
from abx_api.store import get_payload, pg_pool
from conftest import requires_stack

KEY_A = base64.b64encode(b"a" * 32).decode()
KEY_B = base64.b64encode(b"b" * 32).decode()


@pytest.fixture
def keyring_of(monkeypatch):
    """Point the crypto module at a chosen keyring."""

    def configure(active: str, retired: str = ""):
        payload_crypto._cached_keyring.cache_clear()
        monkeypatch.setattr(
            payload_crypto,
            "settings",
            SimpleNamespace(payload_master_key=active, payload_retired_keys=retired),
        )
        return payload_crypto.keyring()

    yield configure
    payload_crypto._cached_keyring.cache_clear()


# -- keyring parsing ----------------------------------------------------------

def test_a_bare_key_keeps_the_legacy_id() -> None:
    """An existing single-key deployment must keep working with no backfill:
    its segments are already stamped 'k1'."""
    ring = parse_keyring(KEY_A)
    assert ring.active_id == payload_crypto.LEGACY_KEY_ID == "k1"
    assert ring.retired_ids == []


def test_retired_keys_are_parsed_and_kept_for_reads() -> None:
    ring = parse_keyring(f"k2:{KEY_B}", f"k1:{KEY_A}")
    assert ring.active_id == "k2"
    assert ring.retired_ids == ["k1"]
    assert ring.get("k1") == b"a" * 32


def test_retired_keys_must_carry_an_id() -> None:
    """Without an id there is no way to match a segment to its key."""
    with pytest.raises(MasterKeyError, match="id:base64"):
        parse_keyring(KEY_A, KEY_B)


def test_a_duplicate_id_is_refused() -> None:
    with pytest.raises(MasterKeyError, match="both active and retired"):
        parse_keyring(f"k1:{KEY_A}", f"k1:{KEY_B}")


def test_malformed_and_wrong_length_keys_are_refused() -> None:
    with pytest.raises(MasterKeyError, match="base64"):
        parse_keyring("k1:not base64 !!")
    with pytest.raises(MasterKeyError, match="32 bytes"):
        parse_keyring("k1:" + base64.b64encode(b"short").decode())


def test_an_unknown_key_id_names_itself(keyring_of) -> None:
    ring = keyring_of(f"k2:{KEY_B}")
    with pytest.raises(MasterKeyError, match="k1"):
        ring.get("k1")


# -- sealing and re-wrapping --------------------------------------------------

def test_sealed_payloads_record_the_key_that_wrapped_them(keyring_of) -> None:
    keyring_of(f"k2:{KEY_B}")
    sealed = seal(b"secret body")
    assert sealed.master_key_id == "k2"


def test_a_payload_sealed_under_a_retired_key_still_reads(keyring_of) -> None:
    """The whole point of the retired list."""
    keyring_of(f"k1:{KEY_A}")
    sealed = seal(b"written before rotation")

    keyring_of(f"k2:{KEY_B}", f"k1:{KEY_A}")
    opened = payload_crypto.open_sealed(
        sealed.ciphertext, sealed.wrapped_key, sealed.key_nonce,
        sealed.data_nonce, sealed.master_key_id,
    )
    assert opened == b"written before rotation"


def test_rewrap_moves_a_payload_onto_the_active_key(keyring_of) -> None:
    keyring_of(f"k1:{KEY_A}")
    sealed = seal(b"body")

    keyring_of(f"k2:{KEY_B}", f"k1:{KEY_A}")
    wrapped, nonce, active_id = payload_crypto.rewrap(
        sealed.wrapped_key, sealed.key_nonce, sealed.master_key_id
    )
    assert active_id == "k2"

    # Readable under the new key alone, so the old one can now be dropped.
    keyring_of(f"k2:{KEY_B}")
    assert payload_crypto.open_sealed(
        sealed.ciphertext, wrapped, nonce, sealed.data_nonce, "k2"
    ) == b"body"


def test_rewrap_does_not_touch_the_ciphertext(keyring_of) -> None:
    """Rotation must not rewrite payload objects: that would cost a full
    object rewrite and could corrupt payload bytes."""
    keyring_of(f"k1:{KEY_A}")
    sealed = seal(b"body")
    before = sealed.ciphertext

    keyring_of(f"k2:{KEY_B}", f"k1:{KEY_A}")
    payload_crypto.rewrap(sealed.wrapped_key, sealed.key_nonce, sealed.master_key_id)
    assert sealed.ciphertext == before


def test_a_wrong_key_cannot_open_a_payload(keyring_of) -> None:
    keyring_of(f"k1:{KEY_A}")
    sealed = seal(b"body")
    keyring_of(f"k1:{KEY_B}")  # same id, different key material
    with pytest.raises(Exception):  # noqa: B017 - any AEAD failure is correct
        payload_crypto.open_sealed(
            sealed.ciphertext, sealed.wrapped_key, sealed.key_nonce,
            sealed.data_nonce, "k1",
        )


# -- configuration validation -------------------------------------------------

def _hardened(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "production",
        "require_https": True,
        "admin_key": "a" * 32,
        "github_state_secret": "g" * 32,
        "s3_server_side_encryption": "AES256",
        "payload_master_key": KEY_A,
    }
    base.update(overrides)
    from dataclasses import replace

    return replace(Settings(), **base)  # type: ignore[arg-type]


def test_production_validates_every_retired_key() -> None:
    """A malformed retired key is silently fatal: it only surfaces when
    something tries to read a payload that key wrapped."""
    errors = production_config_errors(
        _hardened(payload_retired_keys="k0:not base64 !!")
    )
    assert any("k0" in error and "base64" in error for error in errors)

    short = base64.b64encode(b"tooshort").decode()
    errors = production_config_errors(_hardened(payload_retired_keys=f"k0:{short}"))
    assert any("32 bytes" in error for error in errors)


def test_production_rejects_retired_keys_without_an_id() -> None:
    errors = production_config_errors(_hardened(payload_retired_keys=KEY_B))
    assert any("id:base64" in error for error in errors)


def test_production_rejects_a_duplicate_key_id() -> None:
    errors = production_config_errors(_hardened(payload_retired_keys=f"k1:{KEY_B}"))
    assert any("configured twice" in error for error in errors)


def test_a_valid_keyring_passes() -> None:
    assert production_config_errors(
        _hardened(payload_master_key=f"k2:{KEY_B}", payload_retired_keys=f"k1:{KEY_A}")
    ) == []


def test_the_dev_key_is_still_rejected_when_it_carries_an_id() -> None:
    """Prefixing an id must not smuggle the committed dev key into production."""
    dev = Settings().payload_master_key
    errors = production_config_errors(_hardened(payload_master_key=f"k9:{dev}"))
    assert any("PAYLOAD_MASTER_KEY" in error for error in errors)


# -- end to end ---------------------------------------------------------------

@requires_stack
def test_rotation_drill_end_to_end(tenant, keyring_of) -> None:
    """Promote, confirm old payloads read, re-wrap, drop the old key."""
    from abx_api.ingest import ingest_events
    from abx_schemas import IngestEvent

    tenant_id, _ = tenant
    keyring_of(f"k1:{KEY_A}")
    session_id = f"rotate-{uuid.uuid4()}"
    ingest_events(tenant_id, [IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "a", "session_id": session_id,
        "seq": 0, "ts": "2026-07-31T00:00:00.000Z", "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {"name": "tools/call", "outcome": "success"},
        "resource_refs": [], "payload": "sensitive body",
    })])

    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT payload_ref, master_key_id FROM payload_segments "
            "WHERE tenant_id=%s ORDER BY payload_ref DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
    assert row is not None
    payload_ref, stamped = str(row[0]), str(row[1])
    assert stamped == "k1"
    assert get_payload(payload_ref) == b"sensitive body"

    # Promote k2, keep k1 for reads.
    keyring_of(f"k2:{KEY_B}", f"k1:{KEY_A}")
    assert get_payload(payload_ref) == b"sensitive body"

    moved = key_rotation.rewrap_all()
    assert moved >= 1
    with pg_pool().connection() as conn:
        after = conn.execute(
            "SELECT master_key_id FROM payload_segments WHERE payload_ref=%s",
            (payload_ref,),
        ).fetchone()
    assert after is not None and str(after[0]) == "k2"

    # k1 can now be dropped and the payload still reads.
    keyring_of(f"k2:{KEY_B}")
    assert get_payload(payload_ref) == b"sensitive body"
    assert key_rotation.unreadable_segments() == []


@requires_stack
def test_dropping_a_key_too_early_fails_loudly(tenant, keyring_of) -> None:
    """The failure this whole phase exists to prevent. Without the guard the
    first symptom would be an unreadable payload during an incident."""
    from abx_api.ingest import ingest_events
    from abx_schemas import IngestEvent

    tenant_id, _ = tenant
    keyring_of(f"k1:{KEY_A}")
    ingest_events(tenant_id, [IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "a",
        "session_id": f"orphan-{uuid.uuid4()}", "seq": 0,
        "ts": "2026-07-31T00:00:00.000Z", "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {"name": "tools/call", "outcome": "success"},
        "resource_refs": [], "payload": "body",
    })])

    # k1 dropped while segments still reference it.
    keyring_of(f"k2:{KEY_B}")
    missing = key_rotation.unreadable_segments()
    assert any(usage.master_key_id == "k1" and usage.segments >= 1 for usage in missing)

    with pytest.raises(RuntimeError, match="permanently unreadable"):
        key_rotation.assert_keyring_covers_stored_payloads()


@requires_stack
def test_erasure_still_destroys_the_only_key(tenant, keyring_of) -> None:
    """Rotation must not weaken crypto-shredding."""
    from abx_api.ingest import ingest_events
    from abx_api.store import delete_payload
    from abx_schemas import IngestEvent

    tenant_id, _ = tenant
    keyring_of(f"k1:{KEY_A}")
    ingest_events(tenant_id, [IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "a",
        "session_id": f"erase-{uuid.uuid4()}", "seq": 0,
        "ts": "2026-07-31T00:00:00.000Z", "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {"name": "tools/call", "outcome": "success"},
        "resource_refs": [], "payload": "erase me",
    })])
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT payload_ref FROM payload_segments WHERE tenant_id=%s "
            "ORDER BY payload_ref DESC LIMIT 1", (tenant_id,),
        ).fetchone()
    payload_ref = str(row[0])

    delete_payload(payload_ref)
    with pg_pool().connection() as conn:
        gone = conn.execute(
            "SELECT count(*) FROM payload_segments WHERE payload_ref=%s", (payload_ref,)
        ).fetchone()
    assert gone is not None and int(gone[0]) == 0
    # No key row means no way back, regardless of which master key is active.
    assert key_rotation.rewrap_all() == 0


@requires_stack
def test_rewrap_never_puts_a_plaintext_data_key_anywhere_readable(
    tenant, keyring_of, caplog
) -> None:
    """Re-wrap decrypts a data key in memory to re-encrypt it under the new
    master key. That plaintext DEK is the one thing that must never be written
    down: it opens the payload without any master key at all, so a copy of it in
    a log line or an exported bundle undoes envelope encryption entirely.

    The DEK is recovered here through the same unwrap the pipeline uses, so the
    value searched for is the real one. Searching for a value that was never the
    key would pass no matter what re-wrap wrote.
    """
    import logging

    from abx_api.ingest import ingest_events
    from abx_api.payload_crypto import unwrap_key
    from abx_schemas import IngestEvent

    tenant_id, _ = tenant
    keyring_of(f"k1:{KEY_A}")
    ingest_events(tenant_id, [IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "a",
        "session_id": f"rewrap-{uuid.uuid4()}", "seq": 0,
        "ts": "2026-07-31T00:00:00.000Z", "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {"name": "tools/call", "outcome": "success"},
        "resource_refs": [], "payload": "wrapped body",
    })])

    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT wrapped_key, key_nonce, master_key_id FROM payload_segments "
            "WHERE tenant_id=%s ORDER BY payload_ref DESC LIMIT 1", (tenant_id,),
        ).fetchone()
    assert row is not None
    dek = unwrap_key(bytes(row[0]), bytes(row[1]), str(row[2]))
    assert len(dek) == 32, "the recovered value is not a data key, so this proves nothing"

    keyring_of(f"k2:{KEY_B}", retired=f"k1:{KEY_A}")
    with caplog.at_level(logging.DEBUG):
        assert key_rotation.rewrap_all() >= 1

    encoded = {
        dek.hex(),
        base64.b64encode(dek).decode(),
        base64.b64encode(dek).decode().rstrip("="),
        repr(dek),
    }
    logged = caplog.text
    for form in encoded:
        assert form not in logged, "re-wrap logged the plaintext data key"

    # And it is not in the database either: the column holds the WRAPPED key,
    # so the plaintext appearing there would mean the wrap was skipped.
    with pg_pool().connection() as conn:
        stored = conn.execute(
            "SELECT wrapped_key FROM payload_segments WHERE tenant_id=%s", (tenant_id,)
        ).fetchall()
    for (wrapped,) in stored:
        assert bytes(wrapped) != dek, "the data key was stored unwrapped"
        assert dek not in bytes(wrapped), "the plaintext data key is inside the wrapped blob"
