"""Postgres access for the scanner. Separate tiny helper so the scanner does
not import the API package. Every query is tenant-scoped by construction.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg

DSN = os.environ.get("ABX_PG_DSN", "postgresql://abx:abx_dev_password@localhost:5432/abx")


def connect_raw() -> psycopg.Connection:
    """Open a bare connection; caller is responsible for closing it."""
    return psycopg.connect(DSN)


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
    conn = connect_raw()
    try:
        yield conn
    finally:
        conn.close()
