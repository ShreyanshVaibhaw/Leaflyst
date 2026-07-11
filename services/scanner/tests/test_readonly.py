import boto3
import pytest
from abx_scanner.readonly import ReadOnlyViolation, guarded_session
from moto import mock_aws


@mock_aws
def test_read_operations_allowed() -> None:
    session, counter = guarded_session(boto3.session.Session())
    iam = session.client("iam", region_name="us-east-1")
    iam.list_users()  # allowed
    assert counter.count >= 1


@mock_aws
def test_write_operation_blocked() -> None:
    session, _ = guarded_session(boto3.session.Session())
    iam = session.client("iam", region_name="us-east-1")
    # Any mutating call must raise before reaching AWS - the scan path is
    # read-only by construction (Phase 3 exit criterion: zero writes).
    with pytest.raises(ReadOnlyViolation):
        iam.create_user(UserName="should-not-happen")
    with pytest.raises(ReadOnlyViolation):
        iam.delete_user(UserName="whatever")
    with pytest.raises(ReadOnlyViolation):
        iam.put_user_policy(UserName="x", PolicyName="y", PolicyDocument="{}")


@mock_aws
def test_call_counter_counts_reads() -> None:
    session, counter = guarded_session(boto3.session.Session())
    iam = session.client("iam", region_name="us-east-1")
    iam.list_users()
    iam.list_roles()
    assert counter.count == 2
