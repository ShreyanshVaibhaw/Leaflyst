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

KEY LIFECYCLE (blueprint2 13.3). For a product whose erasure guarantee is
"destroy the key", the key lifecycle is load-bearing infrastructure rather than
an operational detail. Master keys are a KEYRING, not a single value:

- exactly one ACTIVE key, used to wrap every new DEK;
- any number of RETIRED keys, kept so previously written payloads stay
  readable;
- every segment records WHICH master key wrapped it, so rotation is possible
  at all. Without that id, changing the master key would silently render every
  stored payload permanently unreadable with no way to detect it beforehand.

Re-wrapping touches only the wrapped DEK, never the payload object, so rotation
costs no object rewrite and cannot corrupt payload bytes. A plaintext DEK is
never persisted anywhere, including during re-wrap.

`wrap_key`/`unwrap_key` remain the seam where a KMS replaces local wrapping
without touching callers.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from abx_api.settings import settings

KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # GCM standard nonce length

# Segments written before the keyring existed were wrapped by the single
# configured master key. They read as this id, and the active key of a
# single-key configuration keeps that id, so no backfill is required.
LEGACY_KEY_ID = "k1"


class MasterKeyError(RuntimeError):
    """The configured payload master keyring is missing or malformed."""


@dataclass(frozen=True)
class Keyring:
    """Master keys by id, with exactly one active for new writes."""

    keys: dict[str, bytes]
    active_id: str

    def get(self, key_id: str) -> bytes:
        key = self.keys.get(key_id)
        if key is None:
            raise MasterKeyError(
                f"payload segments reference master key '{key_id}', which is not in "
                "the configured keyring; add it back or the payloads it wrapped "
                "cannot be read"
            )
        return key

    @property
    def active(self) -> bytes:
        return self.keys[self.active_id]

    @property
    def retired_ids(self) -> list[str]:
        return sorted(key_id for key_id in self.keys if key_id != self.active_id)


def parse_keyring(active_spec: str, retired_spec: str = "") -> Keyring:
    """Build a keyring from configuration.

    Active is ``[id:]base64`` and retired is a comma-separated list of the
    same. The id is optional on the active key so an existing single-key
    deployment keeps working unchanged and its segments keep reading.
    """
    keys: dict[str, bytes] = {}
    active_id, active_key = _parse_entry(active_spec, default_id=LEGACY_KEY_ID)
    keys[active_id] = active_key
    for entry in retired_spec.split(","):
        if not entry.strip():
            continue
        key_id, key = _parse_entry(entry, default_id=None)
        if key_id == active_id:
            raise MasterKeyError(
                f"master key id '{key_id}' is both active and retired; a key id must "
                "identify exactly one key or rotation is ambiguous"
            )
        keys[key_id] = key
    return Keyring(keys=keys, active_id=active_id)


def _parse_entry(spec: str, default_id: str | None) -> tuple[str, bytes]:
    raw = spec.strip()
    if not raw:
        raise MasterKeyError("a payload master key entry is empty")
    if ":" in raw:
        key_id, _, encoded = raw.partition(":")
        key_id = key_id.strip()
    elif default_id is not None:
        key_id, encoded = default_id, raw
    else:
        raise MasterKeyError(
            "retired payload master keys must be given as 'id:base64' so segments "
            "can be matched to the key that wrapped them"
        )
    if not key_id:
        raise MasterKeyError("a payload master key id is empty")
    try:
        key = base64.b64decode(encoded.strip(), validate=True)
    except Exception as exc:
        raise MasterKeyError(
            f"payload master key '{key_id}' must be base64-encoded {KEY_BYTES} bytes"
        ) from exc
    if len(key) != KEY_BYTES:
        raise MasterKeyError(
            f"payload master key '{key_id}' must decode to {KEY_BYTES} bytes, "
            f"got {len(key)}"
        )
    return key_id, key


@lru_cache(maxsize=1)
def _cached_keyring(active_spec: str, retired_spec: str) -> Keyring:
    return parse_keyring(active_spec, retired_spec)


def keyring() -> Keyring:
    return _cached_keyring(settings.payload_master_key, settings.payload_retired_keys)


@dataclass(frozen=True)
class SealedPayload:
    """An encrypted payload body plus everything needed to open it again."""

    ciphertext: bytes
    wrapped_key: bytes
    key_nonce: bytes
    data_nonce: bytes
    master_key_id: str


def new_data_key() -> bytes:
    return os.urandom(KEY_BYTES)


def wrap_key(dek: bytes) -> tuple[bytes, bytes, str]:
    """Wrap a data key with the ACTIVE master key.

    Returns (wrapped, nonce, master_key_id).
    """
    ring = keyring()
    nonce = os.urandom(NONCE_BYTES)
    return AESGCM(ring.active).encrypt(nonce, dek, None), nonce, ring.active_id


def unwrap_key(wrapped: bytes, nonce: bytes, master_key_id: str = LEGACY_KEY_ID) -> bytes:
    return AESGCM(keyring().get(master_key_id)).decrypt(nonce, wrapped, None)


def seal(body: bytes) -> SealedPayload:
    """Encrypt one payload body under a fresh per-payload data key."""
    dek = new_data_key()
    data_nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(data_nonce, body, None)
    wrapped_key, key_nonce, master_key_id = wrap_key(dek)
    return SealedPayload(
        ciphertext=ciphertext,
        wrapped_key=wrapped_key,
        key_nonce=key_nonce,
        data_nonce=data_nonce,
        master_key_id=master_key_id,
    )


def open_sealed(
    ciphertext: bytes,
    wrapped_key: bytes,
    key_nonce: bytes,
    data_nonce: bytes,
    master_key_id: str = LEGACY_KEY_ID,
) -> bytes:
    dek = unwrap_key(wrapped_key, key_nonce, master_key_id)
    return AESGCM(dek).decrypt(data_nonce, ciphertext, None)


def rewrap(
    wrapped_key: bytes, key_nonce: bytes, master_key_id: str
) -> tuple[bytes, bytes, str]:
    """Re-wrap an existing DEK under the active master key.

    Unwraps with the key that originally wrapped it and re-wraps with the
    active one. The payload object is never touched, so rotation is cheap and
    cannot corrupt payload bytes. The plaintext DEK exists only in memory here
    and is never persisted or logged.
    """
    dek = unwrap_key(wrapped_key, key_nonce, master_key_id)
    return wrap_key(dek)
