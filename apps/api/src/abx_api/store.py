"""Shared clients: Postgres pool, ClickHouse client, S3 payload/anchor store."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any

import boto3
import clickhouse_connect
from botocore.config import Config
from psycopg_pool import ConnectionPool

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
        config=Config(connect_timeout=2, read_timeout=2, retries={"max_attempts": 1}),
    )


def put_payload(tenant_id: str, event_id: str, body: bytes) -> str:
    """Store a redacted payload body; returns the payload_ref."""
    key = f"{tenant_id}/{event_id}"
    encryption = (
        {"ServerSideEncryption": settings.s3_server_side_encryption}
        if settings.s3_server_side_encryption
        else {}
    )
    s3_client().put_object(Bucket=settings.payload_bucket, Key=key, Body=body, **encryption)
    return key


def get_payload(payload_ref: str) -> bytes | None:
    try:
        obj = s3_client().get_object(Bucket=settings.payload_bucket, Key=payload_ref)
    except s3_client().exceptions.NoSuchKey:
        return None
    return obj["Body"].read()  # type: ignore[no-any-return]


def delete_payload(payload_ref: str) -> None:
    """Erasure path: payload bodies are deletable; the chain stays verifiable."""
    s3_client().delete_object(Bucket=settings.payload_bucket, Key=payload_ref)


def ensure_buckets() -> None:
    s3 = s3_client()
    existing = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
    if settings.payload_bucket not in existing:
        s3.create_bucket(Bucket=settings.payload_bucket)
    if settings.anchor_bucket not in existing:
        # Object lock requires versioning and can only be enabled at creation.
        s3.create_bucket(Bucket=settings.anchor_bucket, ObjectLockEnabledForBucket=True)
