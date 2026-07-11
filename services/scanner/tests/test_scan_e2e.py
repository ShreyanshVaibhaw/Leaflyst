"""Phase 3 exit criteria: full scan of a seeded account, read-only, with the
PocketOS over-privileged token correctly flagged and blast radius computed,
and re-scans idempotent.
"""

from __future__ import annotations

import time

import boto3
from abx_scanner.db import connect
from abx_scanner.scan import run_aws_scan
from conftest import requires_pg, seed_account
from moto import mock_aws

pytestmark = requires_pg


def _findings(tenant_id: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT finding_type, natural_key, severity, evidence FROM findings "
            "WHERE tenant_id = %s ORDER BY finding_type, natural_key",
            (tenant_id,),
        ).fetchall()
    return [
        {"type": r[0], "key": r[1], "severity": r[2], "evidence": r[3]} for r in rows
    ]


@mock_aws
def test_full_scan_flags_pocketos_token(tenant: str) -> None:
    boto3.client("iam", region_name="us-east-1")  # init moto backend
    seed_account(boto3.client("iam", region_name="us-east-1"))

    start = time.monotonic()
    summary = run_aws_scan(tenant, session=boto3.session.Session())
    elapsed = time.monotonic() - start

    # <10 min budget (this runs in well under a second on a mock).
    assert elapsed < 600
    assert summary.api_calls > 0
    assert summary.credentials == 3

    findings = _findings(tenant)
    types = {f["type"] for f in findings}
    assert "over_privileged" in types
    assert "blast_radius" in types

    overpriv = [f for f in findings if f["type"] == "over_privileged"]
    # The svc-langgraph-07 key is the PocketOS-shaped over-scoped credential.
    assert any("langgraph" in f["evidence"]["principal"] for f in overpriv)
    pocket = next(f for f in overpriv if "langgraph" in f["evidence"]["principal"])
    assert pocket["severity"] == "critical"  # admin wildcard (s3:* on *)
    # Blast radius reached the everything-resource.
    assert pocket["evidence"]["reach_count"] >= 1
    assert any("aws:" in r for r in pocket["evidence"]["reachable_resources"])

    # The scoped agent must NOT be flagged over-privileged.
    assert not any("billing-bot" in f["evidence"]["principal"] for f in overpriv)


@mock_aws
def test_scan_is_idempotent(tenant: str) -> None:
    seed_account(boto3.client("iam", region_name="us-east-1"))
    session = boto3.session.Session()

    run_aws_scan(tenant, session=session)
    first = _findings(tenant)
    with connect() as conn:
        perms1 = conn.execute(
            "SELECT count(*) FROM permissions WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]

    run_aws_scan(tenant, session=session)
    second = _findings(tenant)
    with connect() as conn:
        perms2 = conn.execute(
            "SELECT count(*) FROM permissions WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]

    # Same findings, no duplication of graph rows.
    assert {f["key"] for f in first} == {f["key"] for f in second}
    assert len(first) == len(second)
    assert perms1 == perms2


@mock_aws
def test_scan_records_readonly_run(tenant: str) -> None:
    seed_account(boto3.client("iam", region_name="us-east-1"))
    summary = run_aws_scan(tenant, session=boto3.session.Session())
    with connect() as conn:
        row = conn.execute(
            "SELECT status, api_calls FROM scan_runs WHERE id = %s",
            (summary.scan_run_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == "succeeded"
    assert row[1] == summary.api_calls > 0


@mock_aws
def test_agent_attribution(tenant: str) -> None:
    seed_account(boto3.client("iam", region_name="us-east-1"))
    run_aws_scan(tenant, session=boto3.session.Session())
    with connect() as conn:
        agents = {
            r[0] for r in conn.execute(
                "SELECT name FROM agents WHERE tenant_id = %s", (tenant,)
            ).fetchall()
        }
    # Agenty names attributed; all three seeded users are service-like
    # (programmatic-only with keys), so all are agents at MVP heuristics.
    assert "svc-langgraph-07" in agents
    assert "agent-billing-bot" in agents
