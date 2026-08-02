"""Read-only Microsoft Entra ID service-principal and role-assignment enumeration.

Closest in shape to the AWS scanner: a principal holds long-lived credentials
(client secrets and certificates) and reaches resources through role
assignments with an explicit scope.

Entra's advantage over Google Workspace is that credential expiry IS exposed,
so staleness can be reported from the provider rather than inferred. What is
NOT exposed is a per-credential last-used timestamp: sign-in logs carry that
and require Entra ID P1 plus AuditLog.Read.All. The gap is stated in the scan
notes rather than papered over with an age heuristic pretending to be usage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from abx_scanner.azure_client import AzureClient

TENANT_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
SUBSCRIPTION_ID = re.compile(r"^[0-9a-fA-F-]{36}$")

# Role definition ids that carry write or full control at any scope.
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE = "b24988ac-6180-42a0-ab88-20f7382dd24c"
USER_ACCESS_ADMIN_ROLE = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
PRIVILEGED_ROLES = {OWNER_ROLE, CONTRIBUTOR_ROLE, USER_ACCESS_ADMIN_ROLE}


@dataclass(frozen=True)
class AzureCredential:
    key_id: str
    kind: str  # client_secret | certificate
    display_name: str
    created_at: datetime | None
    expires_at: datetime | None

    @property
    def fingerprint(self) -> str:
        return f"azkey:{self.key_id}"

    def expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now


@dataclass(frozen=True)
class AzureRoleAssignment:
    role_definition_id: str
    role_name: str
    scope: str
    access: str


@dataclass
class AzureServicePrincipal:
    object_id: str
    app_id: str
    display_name: str
    disabled: bool
    credentials: list[AzureCredential] = field(default_factory=list)
    assignments: list[AzureRoleAssignment] = field(default_factory=list)


@dataclass
class AzureScanResult:
    tenant: str
    subscription_id: str
    service_principals: list[AzureServicePrincipal]
    api_calls: int
    notes: list[str] = field(default_factory=list)


def _dt(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _graph_pages(client: AzureClient, path: str, params: dict[str, str]) -> list[dict[str, Any]]:
    """Follow @odata.nextLink, which Graph returns as an absolute URL."""
    items: list[dict[str, Any]] = []
    page = client.graph_get(path, params)
    while True:
        values = page.get("value", [])
        if isinstance(values, list):
            items.extend(value for value in values if isinstance(value, dict))
        next_link = page.get("@odata.nextLink")
        if not isinstance(next_link, str) or not next_link:
            return items
        remainder = next_link.split("graph.microsoft.com", 1)[-1]
        page = client.graph_get(remainder.split("?")[0], _query_of(remainder))


def _query_of(url: str) -> dict[str, str]:
    if "?" not in url:
        return {}
    from urllib.parse import parse_qsl

    return dict(parse_qsl(url.split("?", 1)[1]))


def _role_access(role_definition_id: str, role_name: str) -> str:
    if role_definition_id in {OWNER_ROLE, USER_ACCESS_ADMIN_ROLE}:
        return "admin"
    if role_definition_id == CONTRIBUTOR_ROLE:
        return "write"
    name = role_name.lower()
    if "owner" in name or "admin" in name:
        return "admin"
    if any(marker in name for marker in ("reader", "viewer", "read")):
        return "read"
    return "write"


def _credentials(principal: dict[str, Any]) -> list[AzureCredential]:
    found: list[AzureCredential] = []
    for kind, key in (("client_secret", "passwordCredentials"), ("certificate", "keyCredentials")):
        for item in principal.get(key, []) or []:
            if not isinstance(item, dict) or not item.get("keyId"):
                continue
            found.append(AzureCredential(
                key_id=str(item["keyId"]),
                kind=kind,
                display_name=str(item.get("displayName") or ""),
                created_at=_dt(item.get("startDateTime")),
                expires_at=_dt(item.get("endDateTime")),
            ))
    return found


def _assignments(
    client: AzureClient, subscription_id: str, by_principal: dict[str, str]
) -> dict[str, list[AzureRoleAssignment]]:
    """Role assignments for the subscription, grouped by principal object id.

    One listing for the whole subscription rather than one call per principal:
    a tenant with hundreds of service principals would otherwise turn a scan
    into hundreds of round trips.
    """
    payload = client.arm_get(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments",
        {"api-version": "2022-04-01"},
    )
    grouped: dict[str, list[AzureRoleAssignment]] = {}
    for item in payload.get("value", []) or []:
        if not isinstance(item, dict):
            continue
        properties = item.get("properties")
        if not isinstance(properties, dict):
            continue
        principal_object_id = str(properties.get("principalId") or "")
        if principal_object_id not in by_principal:
            continue
        definition = str(properties.get("roleDefinitionId") or "")
        definition_id = definition.rsplit("/", 1)[-1]
        role_name = str(properties.get("roleDefinitionName") or definition_id)
        grouped.setdefault(principal_object_id, []).append(AzureRoleAssignment(
            role_definition_id=definition_id,
            role_name=role_name,
            scope=f"azure:{properties.get('scope') or ''}",
            access=_role_access(definition_id, role_name),
        ))
    return grouped


def enumerate_tenant(
    client: AzureClient, tenant: str, subscription_id: str
) -> AzureScanResult:
    if not TENANT_ID.fullmatch(tenant):
        raise ValueError("invalid Entra tenant id")
    if not SUBSCRIPTION_ID.fullmatch(subscription_id):
        raise ValueError("invalid Azure subscription id")

    rows = _graph_pages(client, "/v1.0/servicePrincipals", {
        "$select": "id,appId,displayName,accountEnabled,servicePrincipalType",
        "$top": "999",
    })
    principals: list[AzureServicePrincipal] = []
    by_object_id: dict[str, str] = {}
    for row in rows:
        object_id = str(row.get("id") or "")
        if not object_id:
            continue
        by_object_id[object_id] = object_id
        principals.append(AzureServicePrincipal(
            object_id=object_id,
            app_id=str(row.get("appId") or ""),
            display_name=str(row.get("displayName") or ""),
            disabled=row.get("accountEnabled") is False,
        ))

    assignments = _assignments(client, subscription_id, by_object_id)
    for principal in principals:
        detail = client.graph_get(
            f"/v1.0/servicePrincipals/{principal.object_id}",
            {"$select": "id,passwordCredentials,keyCredentials"},
        )
        principal.credentials = _credentials(detail)
        principal.assignments = sorted(
            assignments.get(principal.object_id, []),
            key=lambda a: (a.scope, a.role_name),
        )

    return AzureScanResult(
        tenant=tenant,
        subscription_id=subscription_id,
        service_principals=principals,
        api_calls=client.counter.count,
        notes=[
            "Microsoft Graph does not expose a last-used timestamp on service-principal "
            "credentials; sign-in logs carry that and require Entra ID P1 with "
            "AuditLog.Read.All. Expiry and role reach are reported without claiming "
            "usage freshness.",
        ],
    )
