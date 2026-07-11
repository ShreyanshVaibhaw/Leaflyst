"""Read-only enforcement for the AWS scanner (blueprint 3.3, engineering invariant 3).

The scan path must be PROVABLY read-only. Rather than trust that our code only
calls read APIs, we register a botocore `before-call` hook that raises on any
operation not in an explicit read-only allowlist - so a stray write call fails
loudly instead of mutating a customer's account. The same hook counts API
calls for the scan_runs audit record.

This holds regardless of the credentials' IAM permissions (defense in depth on
top of the SecurityAudit/ViewOnlyAccess policies the connect flow attaches).
Revocation lives in a separate module with separate credentials (Phase 7);
these two paths never share a client.
"""

from __future__ import annotations

import threading

import boto3

# Read-only operations the scanner is allowed to call. Anything else raises.
ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    {
        # STS
        "GetCallerIdentity",
        "AssumeRole",
        # IAM enumeration
        "ListUsers",
        "ListRoles",
        "ListAccessKeys",
        "GetAccessKeyLastUsed",
        "GetUser",
        "GetRole",
        "ListUserPolicies",
        "ListAttachedUserPolicies",
        "ListRolePolicies",
        "ListAttachedRolePolicies",
        "GetUserPolicy",
        "GetRolePolicy",
        "GetPolicy",
        "GetPolicyVersion",
        "ListGroupsForUser",
        "ListMFADevices",
        "GenerateCredentialReport",
        "GetCredentialReport",
        # IAM Access Advisor
        "GenerateServiceLastAccessedDetails",
        "GetServiceLastAccessedDetails",
        # IAM Access Analyzer
        "ListAnalyzers",
        "ListFindingsV2",
        "GetFinding",
        "GetFindingV2",
    }
)


class ReadOnlyViolation(RuntimeError):
    """Raised when the scanner attempts a non-allowlisted (write) API call."""


class CallCounter:
    """Thread-safe counter of API calls made through a guarded session."""

    def __init__(self) -> None:
        self._n = 0
        self._lock = threading.Lock()

    def increment(self) -> None:
        with self._lock:
            self._n += 1

    @property
    def count(self) -> int:
        return self._n


def guarded_session(
    session: boto3.session.Session | None = None,
) -> tuple[boto3.session.Session, CallCounter]:
    """Return a boto3 session whose every API call is checked against the
    read-only allowlist, plus the counter recording how many calls were made.
    """
    session = session or boto3.session.Session()
    counter = CallCounter()

    def before_call(model: object, **kwargs: object) -> None:
        op_name = getattr(model, "name", "")
        counter.increment()
        if op_name not in ALLOWED_OPERATIONS:
            raise ReadOnlyViolation(
                f"scanner attempted non-read-only operation {op_name!r}; "
                "the scan path is read-only by construction"
            )

    session.events.register("before-call", before_call)
    return session, counter
