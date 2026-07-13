"""Shared fixtures for integration tests. Skip cleanly without the dev stack."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest


def _stack_up() -> bool:
    try:
        import psycopg
        from abx_api.settings import settings

        with psycopg.connect(settings.pg_dsn, connect_timeout=2):
            pass
        return True
    except Exception:
        return False


requires_stack = pytest.mark.skipif(not _stack_up(), reason="dev stack not running")


def _delete_tenant_data(conn, tenant_id: str) -> None:
    conn.execute(
        "DELETE FROM permission_reaches_resource WHERE permission_id IN "
        "(SELECT id FROM permissions WHERE tenant_id = %s)",
        (tenant_id,),
    )
    conn.execute(
        "DELETE FROM agent_holds_credential WHERE credential_id IN "
        "(SELECT id FROM credentials WHERE tenant_id = %s)",
        (tenant_id,),
    )
    for table in (
        "revocation_actions",
        "alerts",
        "alert_channels",
        "findings",
        "permissions",
        "resources",
        "integration_connections",
        "credentials",
        "principals",
        "agents",
        "scan_runs",
        "session_shares",
        "session_sequences",
        "metering_token_daily",
        "metering_daily",
        "tenant_plans",
        "scan_upload_tokens",
        "ingest_tokens",
        "chain_heads",
        "tenant_members",
        "tenant_settings",
    ):
        conn.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,))  # noqa: S608


@pytest.fixture
def tenant() -> Iterator[tuple[str, str]]:
    """Create a throwaway tenant + ingest token; clean up after."""
    import psycopg
    from abx_api.auth import new_ingest_token
    from abx_api.settings import settings
    from abx_api.store import ensure_buckets

    ensure_buckets()
    token, token_hash = new_ingest_token()
    with psycopg.connect(settings.pg_dsn) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"test-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        assert row is not None
        tenant_id = str(row[0])
        conn.execute(
            "INSERT INTO ingest_tokens (tenant_id, token_hash, label) VALUES (%s, %s, 'test')",
            (tenant_id, token_hash),
        )
        conn.commit()
    yield tenant_id, token
    with psycopg.connect(settings.pg_dsn) as conn:
        demo = conn.execute(
            "DELETE FROM demo_tenants WHERE owner_tenant_id=%s RETURNING demo_tenant_id",
            (tenant_id,),
        ).fetchone()
        if demo is not None:
            _delete_tenant_data(conn, str(demo[0]))
            conn.execute("DELETE FROM tenants WHERE id = %s", (demo[0],))
        _delete_tenant_data(conn, tenant_id)
        conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        conn.commit()
