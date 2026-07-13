"""Dev/admin CLI.

    uv run python -m abx_api.admin create-tenant <name>
    uv run python -m abx_api.admin set-plan <tenant-id> <plan-key>
        <daily-events|unlimited> [per-token-payloads|unlimited]

Creates a tenant plus one write-only ingest token and prints the token ONCE.
Plan assignment is an operator-only database action until a payment control
plane is integrated; the tenant settings API can only read plan state.
"""

from __future__ import annotations

import re
import sys
from uuid import UUID

from abx_api.auth import new_ingest_token
from abx_api.store import ensure_buckets, pg_pool

PLAN_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def create_tenant(name: str) -> None:
    token, token_hash = new_ingest_token()
    with pg_pool().connection() as conn:
        tenant_id = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id", (name,)
        ).fetchone()
        assert tenant_id is not None
        conn.execute(
            "INSERT INTO ingest_tokens (tenant_id, token_hash, label) VALUES (%s, %s, %s)",
            (tenant_id[0], token_hash, "default"),
        )
    ensure_buckets()
    print(f"tenant_id: {tenant_id[0]}")
    print(f"ingest_token (shown once, not stored): {token}")


def set_plan(
    tenant_id: str,
    plan_key: str,
    daily_event_limit: int | None,
    per_token_daily_payload_limit: int | None,
) -> None:
    """Assign an independently metered plan under the tenant ingest lock."""
    UUID(tenant_id)
    if not PLAN_KEY.fullmatch(plan_key):
        raise ValueError("invalid plan key")
    if daily_event_limit is not None and daily_event_limit < 1:
        raise ValueError("daily event limit must be positive")
    if per_token_daily_payload_limit is not None and per_token_daily_payload_limit < 1:
        raise ValueError("per-token daily payload limit must be positive")
    with pg_pool().connection() as conn:
        tenant = conn.execute(
            "SELECT id FROM tenants WHERE id=%s FOR UPDATE", (tenant_id,)
        ).fetchone()
        if tenant is None:
            raise ValueError("tenant not found")
        conn.execute(
            "INSERT INTO tenant_plans "
            "(tenant_id,plan_key,daily_event_limit,per_token_daily_payload_limit) "
            "VALUES (%s,%s,%s,%s) ON CONFLICT (tenant_id) DO UPDATE SET "
            "plan_key=EXCLUDED.plan_key,daily_event_limit=EXCLUDED.daily_event_limit,"
            "per_token_daily_payload_limit=EXCLUDED.per_token_daily_payload_limit,"
            "updated_at=now()",
            (tenant_id, plan_key, daily_event_limit, per_token_daily_payload_limit),
        )
    event_limit_label = daily_event_limit if daily_event_limit is not None else "unlimited"
    payload_limit_label = (
        per_token_daily_payload_limit
        if per_token_daily_payload_limit is not None
        else "unlimited"
    )
    print(
        f"plan updated: tenant={tenant_id} plan={plan_key} "
        f"daily_events={event_limit_label} per_token_payloads={payload_limit_label}"
    )


def main() -> int:
    match sys.argv[1:]:
        case ["create-tenant", name]:
            create_tenant(name)
            return 0
        case ["set-plan", tenant_id, plan_key, raw_events]:
            event_limit = None if raw_events == "unlimited" else int(raw_events)
            set_plan(tenant_id, plan_key, event_limit, event_limit)
            return 0
        case ["set-plan", tenant_id, plan_key, raw_events, raw_payloads]:
            event_limit = None if raw_events == "unlimited" else int(raw_events)
            payload_limit = None if raw_payloads == "unlimited" else int(raw_payloads)
            set_plan(tenant_id, plan_key, event_limit, payload_limit)
            return 0
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
