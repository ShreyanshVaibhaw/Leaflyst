"""AWS IAM enumeration (read-only). Produces intermediate dataclasses that the
graph layer persists. Every boto3 call goes through the read-only guard.

Scan sequence (blueprint 5.3): users -> access keys (+ last-used, create date)
-> attached/inline policy documents; roles -> trust policies; optional Access
Advisor service-last-accessed for granted-but-unused detection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import unquote

import boto3

from abx_scanner.policy import ParsedPolicy, parse_policy_document
from abx_scanner.readonly import CallCounter, guarded_session


@dataclass
class AccessKey:
    access_key_id: str  # non-secret; the fingerprint we store
    created_at: datetime | None
    last_used_at: datetime | None
    status: str  # Active | Inactive


@dataclass
class Principal:
    kind: str  # iam_user | iam_role
    name: str
    arn: str
    access_keys: list[AccessKey] = field(default_factory=list)
    policies: list[ParsedPolicy] = field(default_factory=list)
    # service names granted-but-never-authenticated (Access Advisor); None = unknown
    unused_services: list[str] | None = None
    programmatic_only: bool = True  # no console login profile observed


@dataclass
class AwsScanResult:
    account_id: str
    principals: list[Principal]
    api_calls: int


def _policy_docs_for_user(iam: Any, user_name: str) -> list[ParsedPolicy]:
    policies: list[ParsedPolicy] = []
    for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"]
        policies.append(parse_policy_document(f"inline:{name}", _as_doc(doc)))
    for att in iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []):
        policies.append(_managed_policy(iam, att["PolicyArn"], att["PolicyName"]))
    return policies


def _managed_policy(iam: Any, arn: str, name: str) -> ParsedPolicy:
    meta = iam.get_policy(PolicyArn=arn)["Policy"]
    version = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])
    doc = version["PolicyVersion"]["Document"]
    return parse_policy_document(f"managed:{name}", _as_doc(doc))


def _as_doc(doc: Any) -> dict[str, Any]:
    """Policy documents come back as dicts or URL-encoded JSON strings."""
    if isinstance(doc, dict):
        return doc
    return json.loads(unquote(str(doc)))  # type: ignore[no-any-return]


def enumerate_account(session: boto3.session.Session | None = None) -> AwsScanResult:
    guarded, counter = guarded_session(session)
    iam = guarded.client("iam")
    sts = guarded.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    principals: list[Principal] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            principals.append(_scan_user(iam, user, counter))

    # Roles: trust-policy edges matter for the graph even if MVP findings focus
    # on user access keys. Kept light (no per-role policy expansion yet).
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            principals.append(
                Principal(kind="iam_role", name=role["RoleName"], arn=role["Arn"])
            )

    return AwsScanResult(account_id=account_id, principals=principals, api_calls=counter.count)


def _scan_user(iam: Any, user: dict[str, Any], counter: CallCounter) -> Principal:
    name, arn = user["UserName"], user["Arn"]
    keys: list[AccessKey] = []
    for meta in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
        kid = meta["AccessKeyId"]
        last_used = iam.get_access_key_last_used(AccessKeyId=kid)
        keys.append(
            AccessKey(
                access_key_id=kid,
                created_at=meta.get("CreateDate"),
                last_used_at=last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate"),
                status=meta.get("Status", "Active"),
            )
        )
    policies = _policy_docs_for_user(iam, name)
    return Principal(
        kind="iam_user",
        name=name,
        arn=arn,
        access_keys=keys,
        policies=policies,
        unused_services=_access_advisor(iam, arn),
        programmatic_only=user.get("PasswordLastUsed") is None,
    )


def _access_advisor(iam: Any, arn: str) -> list[str] | None:
    """Services granted but never authenticated. Returns None if unavailable
    (Access Advisor is not always supported, e.g. in mocked environments)."""
    try:
        job = iam.generate_service_last_accessed_details(Arn=arn)
        details = iam.get_service_last_accessed_details(JobId=job["JobId"])
        unused = [
            s["ServiceNamespace"]
            for s in details.get("ServicesLastAccessed", [])
            if not s.get("LastAuthenticated")
        ]
        return unused
    except Exception:
        return None
