"""Scan orchestration: enumerate -> persist graph -> compute findings, with a
scan_runs audit record (the scanner is auditable by its own standard).

    uv run python -m abx_scanner.scan <tenant_id>

Uses ambient AWS credentials (or a boto3 session passed programmatically). The
CloudFormation connect flow provisions a read-only cross-account role; local
dev uses whatever boto3 resolves.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import boto3
import psycopg

from abx_scanner import aws, findings, graph
from abx_scanner.db import connect_raw


@dataclass
class ScanSummary:
    scan_run_id: str
    account_id: str
    principals: int
    credentials: int
    findings: int
    api_calls: int


def run_aws_scan(
    tenant_id: str,
    session: boto3.session.Session | None = None,
    conn: psycopg.Connection | None = None,
) -> ScanSummary:
    owns_conn = conn is None
    conn = conn or connect_raw()
    try:
        scan_run_id = _start_scan_run(conn, tenant_id)
        try:
            result = aws.enumerate_account(session)
            graph.persist(conn, tenant_id, result)
            fs = findings.compute_findings(conn, tenant_id)
            findings.persist_findings(conn, tenant_id, fs)
            cred_count = sum(len(p.access_keys) for p in result.principals)
            _finish_scan_run(conn, scan_run_id, result.api_calls, "succeeded")
            return ScanSummary(
                scan_run_id=scan_run_id,
                account_id=result.account_id,
                principals=len(result.principals),
                credentials=cred_count,
                findings=len(fs),
                api_calls=result.api_calls,
            )
        except Exception:
            _finish_scan_run(conn, scan_run_id, 0, "failed")
            raise
    finally:
        if owns_conn:
            conn.close()


def _start_scan_run(conn: psycopg.Connection, tenant_id: str) -> str:
    row = conn.execute(
        "INSERT INTO scan_runs (tenant_id, provider, scope, status) "
        "VALUES (%s, 'aws', 'account', 'running') RETURNING id",
        (tenant_id,),
    ).fetchone()
    assert row is not None
    conn.commit()
    return str(row[0])


def _finish_scan_run(
    conn: psycopg.Connection, scan_run_id: str, api_calls: int, status: str
) -> None:
    conn.execute(
        "UPDATE scan_runs SET finished_at = now(), api_calls = %s, status = %s WHERE id = %s",
        (api_calls, status, scan_run_id),
    )
    conn.commit()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m abx_scanner.scan <tenant_id>", file=sys.stderr)
        return 2
    summary = run_aws_scan(sys.argv[1])
    print(
        f"account {summary.account_id}: {summary.principals} principals, "
        f"{summary.credentials} credentials, {summary.findings} findings "
        f"({summary.api_calls} read-only API calls)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
