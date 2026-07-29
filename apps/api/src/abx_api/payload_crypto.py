"""Envelope encryption for payload bodies at rest.

Each payload gets its own random data key (DEK). The DEK is stored wrapped
with a master key, alongside the payload's location inside a batch object.

This is what makes per-payload erasure survive batch packing: many payloads
share one immutable object, so the bytes cannot be removed individually, but
deleting a single DEK row renders exactly one payload unrecoverable. Erasure
becomes one atomic database delete instead of a read-modify-write against the
object store - and unlike rewriting the object, it is unaffected by bucket
versioning or backups holding an older copy.

The bytes themselves are removed later, when age-based retention deletes the
whole batch object. Immediate logical erasure, eventual physical deletion.

Only the wrapped DEK is persisted. The master key comes from configuration;
`wrap_key`/`unwrap_key` are the seam where a KMS replaces local wrapping
without touching callers.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from abx_api.settings import settings

KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # GCM standard nonce length


class MasterKeyError(RuntimeError):
    """The configured payload master key is missing or malformed."""


def _master_key() -> bytes:
    raw = settings.payload_master_key
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:  # noqa: BLE001 - surfaced as a config error
        raise MasterKeyError(
            "ABX_PAYLOAD_MASTER_KEY must be base64-encoded 32 bytes"
        ) from exc
    if len(key) != KEY_BYTES:
        raise MasterKeyError(
            f"ABX_PAYLOAD_MASTER_KEY must decode to {KEY_BYTES} bytes, got {len(key)}"
        )
    return key


@dataclass(frozen=True)
class SealedPayload:
    """An encrypted payload body plus everything needed to open it again."""

    ciphertext: bytes
    wrapped_key: bytes
    key_nonce: bytes
    data_nonce: bytes


def new_data_key() -> bytes:
    return os.urandom(KEY_BYTES)


def wrap_key(dek: bytes) -> tuple[bytes, bytes]:
    """Wrap a data key with the master key. Returns (wrapped, nonce)."""
    nonce = os.urandom(NONCE_BYTES)
    return AESGCM(_master_key()).encrypt(nonce, dek, None), nonce


def unwrap_key(wrapped: bytes, nonce: bytes) -> bytes:
    return AESGCM(_master_key()).decrypt(nonce, wrapped, None)


def seal(body: bytes) -> SealedPayload:
    """Encrypt one payload body under a fresh per-payload data key."""
    dek = new_data_key()
    data_nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(data_nonce, body, None)
    wrapped_key, key_nonce = wrap_key(dek)
    return SealedPayload(
        ciphertext=ciphertext,
        wrapped_key=wrapped_key,
        key_nonce=key_nonce,
        data_nonce=data_nonce,
    )


def open_sealed(
    ciphertext: bytes, wrapped_key: bytes, key_nonce: bytes, data_nonce: bytes
) -> bytes:
    dek = unwrap_key(wrapped_key, key_nonce)
    return AESGCM(dek).decrypt(data_nonce, ciphertext, None)
