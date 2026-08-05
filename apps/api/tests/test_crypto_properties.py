"""Cryptographic properties of the payload envelope (plansecurity SP-7).

The gate asks that algorithms, key sizes, random sources, nonce uniqueness,
authenticated encryption, key separation, and error handling be verified
against the implemented design, with no custom primitive permitted.

Reading the module answers most of that, and reading is not a check. These
assert the properties from the outside, so a future change that swaps a
primitive, reuses a nonce, drops authentication, or starts sharing a key fails
here rather than in an incident.
"""

from __future__ import annotations

import inspect

import pytest
from abx_api import payload_crypto
from abx_api.payload_crypto import (
    KEY_BYTES,
    NONCE_BYTES,
    new_data_key,
    open_sealed,
    seal,
    unwrap_key,
    wrap_key,
)
from cryptography.exceptions import InvalidTag

BODY = b"payload body under test"


def _open(sealed) -> bytes:
    return open_sealed(
        sealed.ciphertext, sealed.wrapped_key, sealed.key_nonce,
        sealed.data_nonce, sealed.master_key_id,
    )


# -- algorithms and sizes ------------------------------------------------------

def test_the_declared_sizes_are_aes_256_gcm() -> None:
    assert KEY_BYTES == 32, "not AES-256"
    assert NONCE_BYTES == 12, "not the GCM standard nonce length"
    assert len(new_data_key()) == KEY_BYTES


def test_no_primitive_is_hand_rolled() -> None:
    """A custom primitive is the failure this gate forbids outright.

    The check is on the source rather than on behaviour, because a home-made
    cipher can behave correctly on a round trip and still be broken. What
    matters is that the module delegates to a reviewed implementation.
    """
    source = inspect.getsource(payload_crypto)
    assert "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" in source
    for forbidden in ("def _encrypt", "def _xor", "hashlib.md5", "hashlib.sha1", "random."):
        assert forbidden not in source, f"payload_crypto contains {forbidden}"


def test_keys_and_nonces_come_from_the_os_csprng() -> None:
    """`random` is seeded and predictable; os.urandom is not."""
    source = inspect.getsource(payload_crypto)
    assert "os.urandom" in source
    assert "import random" not in source


# -- nonce and key uniqueness --------------------------------------------------

def test_every_seal_uses_a_fresh_key_and_a_fresh_nonce() -> None:
    """Reusing a key/nonce pair under GCM is catastrophic: it leaks the XOR of
    two plaintexts and allows forgery. Sealing the same body repeatedly is the
    case most likely to expose a cached or derived nonce.
    """
    sealed = [seal(BODY) for _ in range(64)]

    assert len({s.data_nonce for s in sealed}) == len(sealed), "a data nonce repeated"
    assert len({s.key_nonce for s in sealed}) == len(sealed), "a key nonce repeated"

    # Unwrapped, not compared as ciphertext. wrap_key uses a fresh key_nonce
    # every time, so two identical data keys still produce different
    # wrapped_key bytes - comparing those would pass under precisely the
    # regression this line claims to catch.
    keys = {unwrap_key(s.wrapped_key, s.key_nonce, s.master_key_id) for s in sealed}
    assert len(keys) == len(sealed), "a data key repeated"

    # Identical plaintext must not produce identical ciphertext. This follows
    # from the nonce being fresh and is not evidence about the key.
    assert len({s.ciphertext for s in sealed}) == len(sealed), "the ciphertext is deterministic"
    for s in sealed:
        assert len(s.data_nonce) == NONCE_BYTES
        assert _open(s) == BODY


def test_the_data_key_is_per_payload_not_per_tenant_or_process() -> None:
    """Crypto-shredding one payload must not be capable of shredding another.

    If two payloads shared a data key, erasing one would either leave the other
    readable through the surviving copy or destroy it as collateral. Both are
    wrong, and the second is worse.
    """
    first, second = seal(b"one"), seal(b"two")
    assert first.wrapped_key != second.wrapped_key
    assert unwrap_key(first.wrapped_key, first.key_nonce, first.master_key_id) != unwrap_key(
        second.wrapped_key, second.key_nonce, second.master_key_id
    )


# -- authenticated encryption --------------------------------------------------

def _flip(data: bytes, index: int = 0) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


@pytest.mark.parametrize("field", ["ciphertext", "data_nonce", "wrapped_key", "key_nonce"])
def test_any_corrupted_field_fails_closed_rather_than_returning_wrong_bytes(
    field: str,
) -> None:
    """GCM authenticates, so a modified input must raise rather than decrypt.

    The failure mode being ruled out is a decrypt that succeeds and returns
    garbage. Evidence that silently changes under corruption is worse than
    evidence that is unavailable: an unavailable payload is visibly missing,
    and a wrong one is read as fact.
    """
    sealed = seal(BODY)
    corrupted = {
        "ciphertext": sealed.ciphertext, "data_nonce": sealed.data_nonce,
        "wrapped_key": sealed.wrapped_key, "key_nonce": sealed.key_nonce,
    }
    corrupted[field] = _flip(corrupted[field])

    with pytest.raises(InvalidTag):
        open_sealed(
            corrupted["ciphertext"], corrupted["wrapped_key"],
            corrupted["key_nonce"], corrupted["data_nonce"], sealed.master_key_id,
        )


def test_truncated_ciphertext_is_rejected_not_partially_decrypted() -> None:
    """A partial object read is a real operational event - an interrupted
    download or a half-written multipart upload. It must not yield a partial
    payload that looks complete."""
    sealed = seal(BODY * 20)
    with pytest.raises(InvalidTag):
        open_sealed(
            sealed.ciphertext[: len(sealed.ciphertext) // 2], sealed.wrapped_key,
            sealed.key_nonce, sealed.data_nonce, sealed.master_key_id,
        )


def test_the_corruption_tests_are_not_passing_on_an_already_broken_seal() -> None:
    """The negative control. If open_sealed raised for everything, every test
    above would pass while proving nothing."""
    sealed = seal(BODY)
    assert _open(sealed) == BODY


# -- key separation ------------------------------------------------------------

def test_a_data_key_cannot_stand_in_for_a_master_key() -> None:
    """The two layers must not be interchangeable.

    If a data key could unwrap, then compromising one payload's key would reach
    every other payload wrapped under the same master - which is the entire
    property envelope encryption exists to provide.
    """
    sealed = seal(BODY)
    dek = unwrap_key(sealed.wrapped_key, sealed.key_nonce, sealed.master_key_id)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with pytest.raises(InvalidTag):
        # The data key must not open the wrapped key.
        AESGCM(dek).decrypt(sealed.key_nonce, sealed.wrapped_key, None)


def test_wrapping_is_done_by_the_active_key_and_names_it() -> None:
    """A payload that does not record which master key wrapped it cannot be
    re-wrapped or read after a rotation."""
    dek = new_data_key()
    wrapped, nonce, key_id = wrap_key(dek)
    assert key_id, "the wrapping key is not recorded"
    assert unwrap_key(wrapped, nonce, key_id) == dek
    assert wrapped != dek, "the data key was stored unwrapped"
