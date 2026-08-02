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

from abx_scanner import aws, azure, findings, gcp, github, graph, slack, workspace
from abx_scanner.azure_client import AzureClient
from abx_scanner.db import connect_raw
from abx_scanner.gcp_client import GcpClient
from abx_scanner.gh_client import GitHubClient
from abx_scanner.slack_client import SlackClient
from abx_scanner.workspace_client import WorkspaceClient


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


def run_github_scan(
    tenant_id: str,
    org: str,
    client: GitHubClient,
    conn: psycopg.Connection | None = None,
) -> ScanSummary:
    owns_conn = conn is None
    conn = conn or connect_raw()
    try:
        scan_run_id = _start_scan_run(conn, tenant_id, "github", org)
        try:
            result = github.enumerate_org(client, org)
            graph.persist_github(conn, tenant_id, result)
            fs = findings.compute_github_findings(conn, tenant_id)
            findings.persist_findings(conn, tenant_id, fs)
            _finish_scan_run(conn, scan_run_id, result.api_calls, "succeeded")
            return ScanSummary(
                scan_run_id=scan_run_id,
                account_id=org,
                principals=len({c.owner_login for c in result.credentials}),
                credentials=len(result.credentials),
                findings=len(fs),
                api_calls=result.api_calls,
            )
        except Exception:
            _finish_scan_run(conn, scan_run_id, 0, "failed")
            raise
    finally:
        if owns_conn:
            conn.close()


def run_gcp_scan(
    tenant_id: str,
    project_id: str,
    client: GcpClient,
    conn: psycopg.Connection | None = None,
) -> ScanSummary:
    owns_conn = conn is None
    conn = conn or connect_raw()
    try:
        scan_run_id = _start_scan_run(conn, tenant_id, "gcp", project_id)
        try:
            result = gcp.enumerate_project(client, project_id)
            graph.persist_gcp(conn, tenant_id, result)
            computed = findings.compute_gcp_findings(conn, tenant_id)
            findings.persist_findings(conn, tenant_id, computed)
            credential_count = sum(
                len(account.keys) for account in result.service_accounts
            )
            _finish_scan_run(conn, scan_run_id, result.api_calls, "succeeded")
            return ScanSummary(
                scan_run_id=scan_run_id,
                account_id=project_id,
                principals=len(result.service_accounts),
                credentials=credential_count,
                findings=len(computed),
                api_calls=result.api_calls,
            )
        except Exception:
            _finish_scan_run(conn, scan_run_id, 0, "failed")
            raise
    finally:
        if owns_conn:
            conn.close()


def run_azure_scan(
    tenant_id: str,
    tenant: str,
    subscription_id: str,
    client: AzureClient,
    conn: psycopg.Connection | None = None,
) -> ScanSummary:
    owns_conn = conn is None
    conn = conn or connect_raw()
    try:
        scan_run_id = _start_scan_run(conn, tenant_id, "azure", subscription_id)
        try:
            result = azure.enumerate_tenant(client, tenant, subscription_id)
            graph.persist_azure(conn, tenant_id, result)
            computed = findings.compute_azure_findings(conn, tenant_id)
            findings.persist_findings(conn, tenant_id, computed)
            credential_count = sum(
                len(principal.credentials) for principal in result.service_principals
            )
            _finish_scan_run(conn, scan_run_id, result.api_calls, "succeeded")
            return ScanSummary(
                scan_run_id=scan_run_id,
                account_id=subscription_id,
                principals=len(result.service_principals),
                credentials=credential_count,
                findings=len(computed),
                api_calls=result.api_calls,
            )
        except Exception:
            _finish_scan_run(conn, scan_run_id, 0, "failed")
            raise
    finally:
        if owns_conn:
            conn.close()


def run_workspace_scan(
    tenant_id: str,
    domain: str,
    client: WorkspaceClient,
    conn: psycopg.Connection | None = None,
) -> ScanSummary:
    owns_conn = conn is None
    conn = conn or connect_raw()
    try:
        scan_run_id = _start_scan_run(conn, tenant_id, "workspace", domain)
        try:
            result = workspace.enumerate_domain(client, domain)
            graph.persist_workspace(conn, tenant_id, result)
            computed = findings.compute_workspace_findings(conn, tenant_id)
            findings.persist_findings(conn, tenant_id, computed)
            _finish_scan_run(conn, scan_run_id, result.api_calls, "succeeded")
            return ScanSummary(
                scan_run_id=scan_run_id,
                account_id=domain,
                principals=len({grant.user_email for grant in result.grants}),
                credentials=len(result.grants),
                findings=len(computed),
                api_calls=result.api_calls,
            )
        except Exception:
            _finish_scan_run(conn, scan_run_id, 0, "failed")
            raise
    finally:
        if owns_conn:
            conn.close()


def run_slack_scan(
    tenant_id: str,
    client: SlackClient,
    conn: psycopg.Connection | None = None,
) -> ScanSummary:
    owns_conn = conn is None
    conn = conn or connect_raw()
    try:
        scan_run_id = _start_scan_run(conn, tenant_id, "slack", "enterprise")
        try:
            result = slack.enumerate_enterprise(client)
            graph.persist_slack(conn, tenant_id, result)
            computed = findings.compute_slack_findings(conn, tenant_id)
            findings.persist_findings(conn, tenant_id, computed)
            _finish_scan_run(conn, scan_run_id, result.api_calls, "succeeded")
            return ScanSummary(
                scan_run_id=scan_run_id,
                account_id=result.enterprise_id,
                principals=len(result.apps),
                credentials=len(result.apps),
                findings=len(computed),
                api_calls=result.api_calls,
            )
        except Exception:
            _finish_scan_run(conn, scan_run_id, 0, "failed")
            raise
    finally:
        if owns_conn:
            conn.close()


def _start_scan_run(
    conn: psycopg.Connection, tenant_id: str, provider: str = "aws", scope: str = "account"
) -> str:
    row = conn.execute(
        "INSERT INTO scan_runs (tenant_id, provider, scope, status) "
        "VALUES (%s, %s, %s, 'running') RETURNING id",
        (tenant_id, provider, scope),
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
