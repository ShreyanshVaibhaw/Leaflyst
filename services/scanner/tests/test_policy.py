from abx_scanner.policy import (
    is_admin_wildcard,
    is_destructive,
    normalize_resource,
    parse_policy_document,
)


def test_parse_expands_actions_and_resources() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"],
             "Resource": ["arn:aws:s3:::a", "arn:aws:s3:::b"]},
            {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
        ],
    }
    parsed = parse_policy_document("p", doc)
    # 2 actions x 2 resources from the Allow; Deny ignored.
    assert len(parsed.grants) == 4
    assert all(g.action.startswith("s3:") for g in parsed.grants)


def test_single_action_and_resource_normalized_to_list() -> None:
    doc = {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
    parsed = parse_policy_document("p", doc)
    assert len(parsed.grants) == 1
    assert parsed.grants[0].action == "s3:*"


def test_is_destructive() -> None:
    assert is_destructive("s3:DeleteBucket")
    assert is_destructive("ec2:TerminateInstances")
    assert is_destructive("s3:*")
    assert is_destructive("*")
    assert is_destructive("s3:PutObject")
    assert not is_destructive("s3:GetObject")
    assert not is_destructive("s3:ListBucket")
    assert not is_destructive("iam:GenerateCredentialReport")


def test_is_admin_wildcard() -> None:
    assert is_admin_wildcard("*", "*")
    assert is_admin_wildcard("s3:*", "*")
    assert not is_admin_wildcard("s3:*", "arn:aws:s3:::b")
    assert not is_admin_wildcard("s3:GetObject", "*")


def test_normalize_resource() -> None:
    ident, prov, kind, env = normalize_resource("arn:aws:s3:::prod-data/key/path")
    assert ident == "aws:s3:prod-data"
    assert kind == "s3_bucket"
    assert env == "prod"

    ident, _, kind, _ = normalize_resource("*")
    assert ident == "aws:*:*"
    assert kind == "all"

    _, _, _, env = normalize_resource("arn:aws:rds:us-east-1:1:db:staging-pg")
    assert env == "staging"
