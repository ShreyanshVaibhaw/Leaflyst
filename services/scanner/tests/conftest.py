"""Scanner test fixtures: a throwaway Postgres tenant + a moto-mocked AWS
account seeded with a realistic mix of agent credentials.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import boto3
import pytest


def _pg_up() -> bool:
    try:
        from abx_scanner.db import connect

        with connect():
            return True
    except Exception:
        return False


requires_pg = pytest.mark.skipif(not _pg_up(), reason="postgres dev stack not running")


@pytest.fixture
def tenant() -> Iterator[str]:
    from abx_scanner.db import connect

    with connect() as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"scan-test-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        assert row is not None
        tenant_id = str(row[0])
        conn.commit()
    yield tenant_id
    with connect() as conn:
        # Children first (FKs).
        conn.execute(
            "DELETE FROM permission_reaches_resource WHERE permission_id IN "
            "(SELECT id FROM permissions WHERE tenant_id = %s)", (tenant_id,)
        )
        conn.execute(
            "DELETE FROM agent_holds_credential WHERE credential_id IN "
            "(SELECT id FROM credentials WHERE tenant_id = %s)", (tenant_id,)
        )
        for table in (
            "findings", "permissions", "resources", "credentials",
            "principals", "agents", "scan_runs",
        ):
            conn.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,))  # noqa: S608
        conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        conn.commit()


# --- moto-seeded AWS account -------------------------------------------------

POCKETOS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            # Blanket destructive power across all environments - the exact
            # PocketOS failure: agent only needs read on staging.
            "Action": ["s3:*", "rds:DeleteDBInstance", "ec2:TerminateInstances"],
            "Resource": "*",
        }
    ],
}

SCOPED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::staging-data/*",
        }
    ],
}


def seed_account(iam: boto3.client) -> None:
    """A realistic startup account: one over-scoped agent key, one tidy one,
    one orphaned human-ish key."""
    # Over-privileged agent (PocketOS-shaped).
    iam.create_user(UserName="svc-langgraph-07")
    iam.put_user_policy(
        UserName="svc-langgraph-07",
        PolicyName="broad",
        PolicyDocument=_json(POCKETOS_POLICY),
    )
    iam.create_access_key(UserName="svc-langgraph-07")

    # Well-scoped agent.
    iam.create_user(UserName="agent-billing-bot")
    iam.put_user_policy(
        UserName="agent-billing-bot",
        PolicyName="scoped",
        PolicyDocument=_json(SCOPED_POLICY),
    )
    iam.create_access_key(UserName="agent-billing-bot")

    # A plain key with no agenty name and no policy (control).
    iam.create_user(UserName="ci-deploy")
    iam.create_access_key(UserName="ci-deploy")


def _json(doc: dict) -> str:
    import json

    return json.dumps(doc)
