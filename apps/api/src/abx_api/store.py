"""Shared clients: Postgres pool, ClickHouse client, S3 payload/anchor store."""

from __future__ import annotations

import uuid
from functools import lru_cache
from typing import TYPE_CHECKING, Any

import boto3
import clickhouse_connect
from botocore.config import Config
from psycopg_pool import ConnectionPool

from abx_api.payload_crypto import open_sealed
from abx_api.settings import settings

if TYPE_CHECKING:
    from clickhouse_connect.driver.client import Client

EVENT_COLUMNS = [
    "event_id", "tenant_id", "agent_id", "session_id", "seq",
    "ts", "source", "event_type",
    "op_name", "op_provider", "op_target", "op_outcome", "op_duration_ms",
    "credential_ref", "resource_refs", "payload_digest", "payload_ref",
    "payload_truncated", "redactions", "prev_hash", "event_hash", "chain_seq",
]


@lru_cache(maxsize=1)
def pg_pool() -> ConnectionPool:
    return ConnectionPool(settings.pg_dsn, min_size=1, max_size=10, open=True)


@lru_cache(maxsize=1)
def ch_client() -> Client:
    return clickhouse_connect.get_client(
        host=settings.ch_host,
        port=settings.ch_port,
        database=settings.ch_database,
        username=settings.ch_user,
        password=settings.ch_password,
    )


@lru_cache(maxsize=1)
def s3_client() -> Any:
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name="us-east-1",
        config=Config(
            connect_timeout=2,
            read_timeout=2,
            retries={"max_attempts": 1},
            max_pool_connections=16,
        ),
    )


def payload_ref_for(tenant_id: str, event_id: str) -> str:
    """The stable logical id stored on the event.

    Unchanged from the pre-batching layout on purpose: payload_ref is part of
    HASHED_FIELDS, so its format is committed to by every event hash.
    """
    return f"{tenant_id}/{event_id}"


def put_payload_batch(tenant_id: str, bodies: list[bytes]) -> tuple[str, list[int]]:
    """Store many payload bodies as one object.

    Returns the object key and the byte offset of each body, in order. This is
    a single request regardless of how many payloads it carries, which is the
    point: one PUT per payload was ~94% of ingest time.
    """
    key = f"{tenant_id}/batches/{uuid.uuid4()}"
    offsets: list[int] = []
    cursor = 0
    for body in bodies:
        offsets.append(cursor)
        cursor += len(body)
    encryption = (
        {"ServerSideEncryption": settings.s3_server_side_encryption}
        if settings.s3_server_side_encryption
        else {}
    )
    s3_client().put_object(
        Bucket=settings.payload_bucket, Key=key, Body=b"".join(bodies), **encryption
    )
    return key, offsets


def get_payload(payload_ref: str) -> bytes | None:
    """Read one payload body.

    Resolves the logical ref through payload_segments and reads only that
    payload's byte range, so cost stays proportional to the payload rather
    than to the batch it shares. Refs written before batching have no segment
    row and are read directly as object keys.
    """
    with pg_pool().connection() as conn:
        segment = conn.execute(
            "SELECT b.object_key, s.byte_offset, s.byte_length, s.wrapped_key, "
            "s.key_nonce, s.data_nonce FROM payload_segments s "
            "JOIN payload_batches b ON b.id = s.batch_id WHERE s.payload_ref = %s",
            (payload_ref,),
        ).fetchone()

    if segment is None:
        return _get_legacy_payload(payload_ref)

    object_key, offset, length, wrapped_key, key_nonce, data_nonce = segment
    if length == 0:
        ciphertext = b""
    else:
        try:
            obj = s3_client().get_object(
                Bucket=settings.payload_bucket,
                Key=object_key,
                Range=f"bytes={offset}-{offset + length - 1}",
            )
        except s3_client().exceptions.NoSuchKey:
            return None
        ciphertext = obj["Body"].read()
    return open_sealed(ciphertext, bytes(wrapped_key), bytes(key_nonce), bytes(data_nonce))


def _get_legacy_payload(payload_ref: str) -> bytes | None:
    try:
        obj = s3_client().get_object(Bucket=settings.payload_bucket, Key=payload_ref)
    except s3_client().exceptions.NoSuchKey:
        return None
    return obj["Body"].read()  # type: ignore[no-any-return]


def delete_payload(payload_ref: str) -> None:
    """Erasure path: payload bodies are deletable; the chain stays verifiable.

    For batched payloads this deletes the only copy of that payload's data key,
    which is atomic and leaves no window where a crash could resurrect the
    body. The ciphertext is removed with the whole object when retention
    expires the batch. Pre-batching payloads are still deleted directly.
    """
    with pg_pool().connection() as conn:
        deleted = conn.execute(
            "DELETE FROM payload_segments WHERE payload_ref = %s", (payload_ref,)
        ).rowcount
    if not deleted:
        s3_client().delete_object(Bucket=settings.payload_bucket, Key=payload_ref)


def ensure_buckets() -> None:
    s3 = s3_client()
    existing = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
    if settings.payload_bucket not in existing:
        s3.create_bucket(Bucket=settings.payload_bucket)
    if settings.anchor_bucket not in existing:
        # Object lock requires versioning and can only be enabled at creation.
        s3.create_bucket(Bucket=settings.anchor_bucket, ObjectLockEnabledForBucket=True)
