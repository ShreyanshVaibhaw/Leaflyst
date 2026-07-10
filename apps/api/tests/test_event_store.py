"""Integration test: the events table is append-only for the app user.

Requires the dev stack (docker compose -f infra/docker-compose.dev.yml up -d).
Skips cleanly when ClickHouse is not reachable so unit CI stays green without Docker.
"""

import uuid
from datetime import UTC, datetime

import pytest

clickhouse_connect = pytest.importorskip("clickhouse_connect")

APP_USER = {"username": "abx_app", "password": "abx_app_dev_password"}


def _client() -> "clickhouse_connect.driver.Client":  # type: ignore[name-defined]
    try:
        return clickhouse_connect.get_client(
            host="localhost", port=8123, database="abx", **APP_USER
        )
    except Exception:
        pytest.skip("ClickHouse dev stack not running")


def test_insert_and_read_back() -> None:
    client = _client()
    tenant = str(uuid.uuid4())
    client.insert(
        "events",
        [[
            str(uuid.uuid4()), tenant, "test-agent", "sess-1", 0,
            datetime.now(UTC), "mcp_tap", "mcp_request",
            "tools/call test", "test-server", "test", "success", 5,
            "", ["file:/tmp/x"], "0" * 64, "", False, [], "0" * 64, "1" * 64,
        ]],
        column_names=[
            "event_id", "tenant_id", "agent_id", "session_id", "seq",
            "ts", "source", "event_type",
            "op_name", "op_provider", "op_target", "op_outcome", "op_duration_ms",
            "credential_ref", "resource_refs", "payload_digest", "payload_ref",
            "payload_truncated", "redactions", "prev_hash", "event_hash",
        ],
    )
    rows = client.query(
        "SELECT agent_id, seq FROM events WHERE tenant_id = %(t)s", parameters={"t": tenant}
    ).result_rows
    assert rows == [("test-agent", 0)]


def test_app_user_cannot_mutate() -> None:
    client = _client()
    # ClickHouse mutations are ALTER TABLE ... UPDATE/DELETE; abx_app has no ALTER grant.
    with pytest.raises(Exception, match="ACCESS_DENIED|Not enough privileges|497"):
        client.command("ALTER TABLE events DELETE WHERE 1 = 1")
    with pytest.raises(Exception, match="ACCESS_DENIED|Not enough privileges|497"):
        client.command("ALTER TABLE events UPDATE agent_id = 'x' WHERE 1 = 1")
    with pytest.raises(Exception, match="ACCESS_DENIED|Not enough privileges|497"):
        client.command("TRUNCATE TABLE events")
    with pytest.raises(Exception, match="ACCESS_DENIED|Not enough privileges|497"):
        client.command("DROP TABLE events")
