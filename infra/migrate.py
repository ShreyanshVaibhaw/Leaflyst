"""Tiny forward-only Postgres migration runner.

Applies infra/postgres/migrations/*.sql in filename order, tracking applied
files in schema_migrations. No down migrations; write a new file instead.

Usage: uv run python infra/migrate.py
Env:   ABX_PG_DSN (default: local docker-compose dev instance)
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg

MIGRATIONS = Path(__file__).parent / "postgres" / "migrations"
DSN = os.environ.get("ABX_PG_DSN", "postgresql://abx:abx_dev_password@localhost:5432/abx")


def main() -> None:
    with psycopg.connect(DSN) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        applied = {
            row[0] for row in conn.execute("SELECT filename FROM schema_migrations").fetchall()
        }
        for sql_file in sorted(MIGRATIONS.glob("*.sql")):
            if sql_file.name in applied:
                continue
            print(f"applying {sql_file.name}")
            conn.execute(sql_file.read_text(encoding="utf-8"))  # type: ignore[arg-type]
            conn.execute(
                "INSERT INTO schema_migrations (filename) VALUES (%s)", (sql_file.name,)
            )
        conn.commit()
    print("migrations up to date")


if __name__ == "__main__":
    main()
