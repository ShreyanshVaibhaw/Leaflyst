"""Dev/admin CLI.

    uv run python -m abx_api.admin create-tenant <name>

Creates a tenant plus one write-only ingest token and prints the token ONCE.
"""

from __future__ import annotations

import sys

from abx_api.auth import new_ingest_token
from abx_api.store import ensure_buckets, pg_pool


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


def main() -> int:
    match sys.argv[1:]:
        case ["create-tenant", name]:
            create_tenant(name)
            return 0
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
