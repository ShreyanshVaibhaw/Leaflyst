"""IAM policy parsing and resource/ARN normalization.

Turns policy documents into a flat list of granted (action, resource) pairs,
normalizes AWS ARNs into the graph's resource identifiers, infers a coarse
environment, and flags destructive/admin actions - the raw material the
findings engine reasons over.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Action verbs that can change or destroy state. Matched case-insensitively
# against the action's verb (the part after the service, e.g. s3:DeleteBucket).
_DESTRUCTIVE = re.compile(
    r"(?i)(delete|terminate|remove|destroy|purge|stop|disable|revoke|put|write|create|update|modify)"
)
_READONLY_VERB = re.compile(r"(?i)^(get|list|describe|head|batchget|generate|simulate|view)")

_ENV_PATTERNS = [
    ("prod", re.compile(r"(?i)\b(prod|production|prd)\b|prod")),
    ("staging", re.compile(r"(?i)\b(stag|staging|stg|uat|preprod)\b|staging")),
    ("dev", re.compile(r"(?i)\b(dev|development|test|sandbox|sbx)\b|dev")),
]


@dataclass
class Grant:
    action: str  # e.g. "s3:DeleteBucket" or "*"
    resource: str  # raw ARN or "*"


@dataclass
class ParsedPolicy:
    name: str
    grants: list[Grant] = field(default_factory=list)


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse_policy_document(name: str, doc: dict[str, Any]) -> ParsedPolicy:
    """Flatten a policy document's Allow statements into (action, resource) grants."""
    grants: list[Grant] = []
    for stmt in _as_list(doc.get("Statement")):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action")) or _as_list(stmt.get("NotAction"))
        resources = _as_list(stmt.get("Resource")) or ["*"]
        for action in actions:
            for resource in resources:
                grants.append(Grant(action=str(action), resource=str(resource)))
    return ParsedPolicy(name=name, grants=grants)


def is_destructive(action: str) -> bool:
    """True if the action can change/destroy state (not a pure read)."""
    if action == "*":
        return True
    if ":" not in action:
        return bool(_DESTRUCTIVE.search(action))
    verb = action.split(":", 1)[1]
    if verb == "*":
        return True
    if _READONLY_VERB.match(verb):
        return False
    return bool(_DESTRUCTIVE.search(verb))


def is_admin_wildcard(action: str, resource: str) -> bool:
    """The classic over-privilege smell: broad power over everything."""
    action_all = action == "*" or action.endswith(":*")
    return action_all and resource == "*"


def normalize_resource(arn: str) -> tuple[str, str, str, str]:
    """ARN -> (identifier, provider, kind, environment).

    identifier is the graph's normalized id, e.g. 'aws:s3:my-bucket'.
    '*' becomes the everything-resource 'aws:*:*' (maximum blast radius).
    """
    if arn == "*":
        return "aws:*:*", "aws", "all", "unknown"
    # arn:partition:service:region:account:resource(/qualifier)
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return f"aws:unknown:{arn}", "aws", "unknown", infer_environment(arn)
    service = parts[2]
    resource = parts[5]
    # Keep the resource name but drop wildly specific object keys after the first /.
    resource_head = resource.split("/", 1)[0] if "/" in resource else resource
    kind = _service_kind(service)
    identifier = f"aws:{service}:{resource_head or '*'}"
    return identifier, "aws", kind, infer_environment(arn)


def infer_environment(text: str) -> str:
    for env, pattern in _ENV_PATTERNS:
        if pattern.search(text):
            return env
    return "unknown"


def _service_kind(service: str) -> str:
    return {
        "s3": "s3_bucket",
        "rds": "database",
        "dynamodb": "database",
        "ec2": "compute",
        "lambda": "function",
        "secretsmanager": "secret",
        "iam": "identity",
    }.get(service, service)
