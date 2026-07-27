"""Read-only Google Cloud service-account key and IAM reach enumeration."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

from abx_scanner.gcp_client import GcpClient

PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


@dataclass(frozen=True)
class GcpKey:
    key_id: str
    created_at: datetime | None
    expires_at: datetime | None
    disabled: bool
    algorithm: str
    origin: str

    @property
    def fingerprint(self) -> str:
        return f"gcpkey:{self.key_id}"


@dataclass(frozen=True)
class GcpGrant:
    role: str
    resource: str
    resource_kind: str
    access: str


@dataclass
class GcpServiceAccount:
    email: str
    unique_id: str
    disabled: bool
    keys: list[GcpKey] = field(default_factory=list)
    grants: list[GcpGrant] = field(default_factory=list)


@dataclass
class GcpScanResult:
    project_id: str
    service_accounts: list[GcpServiceAccount]
    api_calls: int
    notes: list[str] = field(default_factory=list)


def _dt(value: object) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _pages(
    getter: Any,
    path: str,
    item_key: str,
    params: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = ""
    while True:
        page_params = dict(params or {})
        if token:
            page_params["pageToken"] = token
        page = getter(path, page_params)
        values = page.get(item_key, [])
        if isinstance(values, list):
            items.extend(value for value in values if isinstance(value, dict))
        token = str(page.get("nextPageToken", ""))
        if not token:
            return items


def _role_access(role: str) -> str:
    name = role.lower()
    if name in {"roles/owner"} or "admin" in name:
        return "admin"
    if name in {"roles/viewer", "roles/browser"} or any(
        marker in name for marker in ("viewer", "reader", "auditor", "reviewer")
    ):
        return "read"
    return "write"


def _grants(client: GcpClient, project_id: str, email: str) -> list[GcpGrant]:
    path = f"/v1/projects/{project_id}:searchAllIamPolicies"
    results = _pages(
        client.asset_get,
        path,
        "results",
        {"query": f"policy:{email}", "pageSize": "500"},
    )
    member = f"serviceAccount:{email}"
    grants: set[GcpGrant] = set()
    for result in results:
        policy = result.get("policy")
        bindings = policy.get("bindings", []) if isinstance(policy, dict) else []
        resource = str(result.get("resource") or result.get("attachedResource") or "")
        asset_type = str(result.get("assetType") or "resource")
        if not resource:
            continue
        for binding in bindings if isinstance(bindings, list) else []:
            if not isinstance(binding, dict) or member not in binding.get("members", []):
                continue
            role = str(binding.get("role", ""))
            if role:
                grants.add(
                    GcpGrant(
                        role=role,
                        resource=f"gcp:{resource}",
                        resource_kind=asset_type.rsplit("/", 1)[-1],
                        access=_role_access(role),
                    )
                )
    return sorted(grants, key=lambda grant: (grant.resource, grant.role))


def enumerate_project(client: GcpClient, project_id: str) -> GcpScanResult:
    if not PROJECT_ID.fullmatch(project_id):
        raise ValueError("invalid Google Cloud project id")
    account_rows = _pages(
        client.iam_get,
        f"/v1/projects/{project_id}/serviceAccounts",
        "accounts",
        {"pageSize": "100"},
    )
    service_accounts: list[GcpServiceAccount] = []
    for row in account_rows:
        email = str(row.get("email", ""))
        if not email:
            continue
        key_rows = client.iam_get(
            f"/v1/projects/{project_id}/serviceAccounts/{quote(email, safe='@')}/keys",
            {"keyTypes": "USER_MANAGED"},
        ).get("keys", [])
        keys = [
            GcpKey(
                key_id=str(key.get("name", "")).rsplit("/", 1)[-1],
                created_at=_dt(key.get("validAfterTime")),
                expires_at=_dt(key.get("validBeforeTime")),
                disabled=bool(key.get("disabled", False)),
                algorithm=str(key.get("keyAlgorithm", "")),
                origin=str(key.get("keyOrigin", "")),
            )
            for key in key_rows
            if isinstance(key, dict) and key.get("name")
        ]
        service_accounts.append(
            GcpServiceAccount(
                email=email,
                unique_id=str(row.get("uniqueId", "")),
                disabled=bool(row.get("disabled", False)),
                keys=keys,
                grants=_grants(client, project_id, email),
            )
        )
    return GcpScanResult(
        project_id=project_id,
        service_accounts=service_accounts,
        api_calls=client.counter.count,
        notes=[
            "Google Cloud does not expose a last-used timestamp on service-account keys; "
            "age and IAM reach are reported without claiming usage freshness."
        ],
    )
