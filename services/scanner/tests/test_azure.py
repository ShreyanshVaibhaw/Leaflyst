"""Read-only Microsoft Entra ID / Azure enumeration.

The load-bearing test here is not that enumeration works - it is that the scan
path CANNOT write. That guarantee is enforced in the client rather than relied
on from IAM alone, so a scan identity misconfigured with write permission still
cannot mutate anything (blueprint 6, invariant 3).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from abx_scanner.azure import enumerate_tenant
from abx_scanner.azure_client import AzureClient, AzureError, Response
from abx_scanner.readonly import ReadOnlyViolation
from conftest import requires_pg

TENANT = "00000000-0000-0000-0000-000000000001"
SUBSCRIPTION = "00000000-0000-0000-0000-000000000002"
SP_ID = "11111111-1111-1111-1111-111111111111"
QUIET_SP_ID = "22222222-2222-2222-2222-222222222222"
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
READER_ROLE = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

NOW = datetime.now(UTC)


def _sp_list() -> dict:
    return {"value": [
        {"id": SP_ID, "appId": "app-1", "displayName": "deploy-bot", "accountEnabled": True},
        {"id": QUIET_SP_ID, "appId": "app-2", "displayName": "reporting",
         "accountEnabled": True},
    ]}


def _sp_detail(object_id: str) -> dict:
    if object_id == SP_ID:
        return {
            "id": SP_ID,
            "passwordCredentials": [{
                "keyId": "secret-1", "displayName": "ci",
                "startDateTime": (NOW - timedelta(days=400)).isoformat(),
                "endDateTime": (NOW + timedelta(days=30)).isoformat(),
            }],
            "keyCredentials": [{
                "keyId": "cert-1", "displayName": "mtls",
                "startDateTime": (NOW - timedelta(days=10)).isoformat(),
                "endDateTime": (NOW - timedelta(days=1)).isoformat(),
            }],
        }
    return {"id": QUIET_SP_ID, "passwordCredentials": [], "keyCredentials": []}


def _assignments() -> dict:
    return {"value": [
        {"properties": {
            "principalId": SP_ID,
            "roleDefinitionId": f"/subscriptions/{SUBSCRIPTION}/providers/"
                                f"Microsoft.Authorization/roleDefinitions/{OWNER_ROLE}",
            "roleDefinitionName": "Owner",
            "scope": f"/subscriptions/{SUBSCRIPTION}",
        }},
        {"properties": {
            "principalId": QUIET_SP_ID,
            "roleDefinitionId": f"/subscriptions/{SUBSCRIPTION}/providers/"
                                f"Microsoft.Authorization/roleDefinitions/{READER_ROLE}",
            "roleDefinitionName": "Reader",
            "scope": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/reports",
        }},
        # A human user's assignment must not be attributed to a principal.
        {"properties": {
            "principalId": "99999999-9999-9999-9999-999999999999",
            "roleDefinitionId": f"/x/{OWNER_ROLE}", "roleDefinitionName": "Owner",
            "scope": f"/subscriptions/{SUBSCRIPTION}",
        }},
    ]}


def fake_opener(seen: list[str] | None = None):
    def open_url(url: str) -> Response:
        if seen is not None:
            seen.append(url)
        if "/roleAssignments" in url:
            body = _assignments()
        elif "/servicePrincipals/" in url:
            body = _sp_detail(url.split("/servicePrincipals/")[1].split("?")[0])
        elif "/servicePrincipals" in url:
            body = _sp_list()
        else:
            return Response(status=404, body=b'{"error":"not found"}')
        return Response(status=200, body=json.dumps(body).encode())

    return open_url


def scan() -> object:
    return enumerate_tenant(AzureClient(opener=fake_opener()), TENANT, SUBSCRIPTION)


# -- the read-only guarantee --------------------------------------------------

def test_client_has_no_write_method() -> None:
    """Absence of a write path is the guarantee. If a mutating helper is ever
    added, this test is the thing that should stop it."""
    client = AzureClient(opener=fake_opener())
    exposed = {name for name in dir(client) if not name.startswith("_")}
    assert exposed == {"opener", "counter", "graph_get", "arm_get"}


def test_non_get_is_refused() -> None:
    client = AzureClient(opener=fake_opener())
    with pytest.raises(ReadOnlyViolation):
        client._request("POST", "https://graph.microsoft.com", "/v1.0/servicePrincipals")
    with pytest.raises(ReadOnlyViolation):
        client._request("DELETE", "https://management.azure.com", "/subscriptions/x")


def test_only_declared_api_roots_are_reachable() -> None:
    client = AzureClient(opener=fake_opener())
    with pytest.raises(ValueError):
        client._request("GET", "https://evil.example.com", "/v1.0/servicePrincipals")
    with pytest.raises(ValueError):
        client.graph_get("/beta/servicePrincipals")
    with pytest.raises(ValueError):
        client.arm_get("/tenants")


def test_a_full_scan_issues_only_get_requests() -> None:
    seen: list[str] = []
    enumerate_tenant(AzureClient(opener=fake_opener(seen)), TENANT, SUBSCRIPTION)
    assert seen, "the scan should have made calls"
    assert all(
        url.startswith(("https://graph.microsoft.com", "https://management.azure.com"))
        for url in seen
    )


# -- enumeration --------------------------------------------------------------

def test_credentials_and_roles_are_enumerated() -> None:
    result = scan()
    principals = {p.object_id: p for p in result.service_principals}
    assert set(principals) == {SP_ID, QUIET_SP_ID}

    deploy = principals[SP_ID]
    assert {c.kind for c in deploy.credentials} == {"client_secret", "certificate"}
    assert [a.role_name for a in deploy.assignments] == ["Owner"]
    assert deploy.assignments[0].access == "admin"

    reporting = principals[QUIET_SP_ID]
    assert reporting.credentials == []
    assert reporting.assignments[0].access == "read"


def test_no_secret_value_is_ever_captured() -> None:
    """Fingerprints only. A key id is not a secret; a secret value would be."""
    result = scan()
    serialized = json.dumps(result, default=lambda o: getattr(o, "__dict__", str(o)))
    for credential in result.service_principals[0].credentials:
        assert credential.fingerprint.startswith("azkey:")
    assert "secretText" not in serialized
    assert "customKeyIdentifier" not in serialized


def test_expiry_is_reported_and_expired_credentials_are_detectable() -> None:
    deploy = next(p for p in scan().service_principals if p.object_id == SP_ID)
    by_kind = {c.kind: c for c in deploy.credentials}
    assert not by_kind["client_secret"].expired(NOW)
    assert by_kind["certificate"].expired(NOW)


def test_last_used_gap_is_disclosed_not_hidden() -> None:
    """Blueprint 2.3: every known visibility gap is stated in-product."""
    notes = " ".join(scan().notes)
    assert "last-used" in notes
    assert "AuditLog.Read.All" in notes


def test_assignments_for_other_principals_are_not_attributed() -> None:
    result = scan()
    scopes = {a.scope for p in result.service_principals for a in p.assignments}
    assert all(scope.startswith("azure:/subscriptions/") for scope in scopes)
    assert sum(len(p.assignments) for p in result.service_principals) == 2


def test_role_assignments_are_listed_once_for_the_subscription() -> None:
    """One listing, not one call per principal: a tenant with hundreds of
    service principals must not turn a scan into hundreds of round trips."""
    seen: list[str] = []
    enumerate_tenant(AzureClient(opener=fake_opener(seen)), TENANT, SUBSCRIPTION)
    assert len([url for url in seen if "/roleAssignments" in url]) == 1


def test_invalid_identifiers_are_rejected_before_any_call() -> None:
    seen: list[str] = []
    client = AzureClient(opener=fake_opener(seen))
    with pytest.raises(ValueError):
        enumerate_tenant(client, "not-a-guid", SUBSCRIPTION)
    with pytest.raises(ValueError):
        enumerate_tenant(client, TENANT, "not-a-guid")
    assert seen == []


def test_api_errors_surface_with_status() -> None:
    def failing(_url: str) -> Response:
        return Response(status=403, body=b'{"error":{"message":"Insufficient privileges"}}')

    with pytest.raises(AzureError) as exc:
        enumerate_tenant(AzureClient(opener=failing), TENANT, SUBSCRIPTION)
    assert exc.value.status == 403


# -- persistence and findings -------------------------------------------------

@requires_pg
def test_scan_persists_graph_and_findings_idempotently(tenant) -> None:
    """Re-running a scan must not duplicate nodes or findings (blueprint 5.3)."""
    from abx_scanner.db import connect
    from abx_scanner.scan import run_azure_scan

    def counts(conn) -> tuple[int, int, int]:
        return tuple(  # type: ignore[return-value]
            conn.execute(
                f"SELECT count(*) FROM {table} WHERE tenant_id = %s", (tenant,)
            ).fetchone()[0]
            for table in ("credentials", "permissions", "findings")
        )

    with connect() as conn:
        first = run_azure_scan(
            tenant, TENANT, SUBSCRIPTION, AzureClient(opener=fake_opener()), conn=conn
        )
        after_first = counts(conn)
        second = run_azure_scan(
            tenant, TENANT, SUBSCRIPTION, AzureClient(opener=fake_opener()), conn=conn
        )
        after_second = counts(conn)

    assert first.principals == 2
    assert first.credentials == 2
    assert after_first == after_second, "re-scanning must be idempotent"
    assert second.findings == first.findings


@requires_pg
def test_over_privileged_owner_is_flagged_and_reader_is_not(tenant) -> None:
    from abx_scanner.db import connect
    from abx_scanner.scan import run_azure_scan

    with connect() as conn:
        run_azure_scan(
            tenant, TENANT, SUBSCRIPTION, AzureClient(opener=fake_opener()), conn=conn
        )
        rows = conn.execute(
            "SELECT f.finding_type, f.severity, f.natural_key FROM findings f "
            "WHERE f.tenant_id = %s ORDER BY f.natural_key", (tenant,),
        ).fetchall()

    kinds = {row[0] for row in rows}
    assert "over_privileged" in kinds
    # The Owner-holding secret is critical; the Reader principal has no
    # credentials and must not generate a privilege finding.
    over = [row for row in rows if row[0] == "over_privileged"]
    assert all(row[1] == "critical" for row in over)
    assert all("secret-1" in row[2] or "cert-1" in row[2] for row in over)


@requires_pg
def test_expired_credential_on_a_privileged_principal_is_flagged(tenant) -> None:
    from abx_scanner.db import connect
    from abx_scanner.scan import run_azure_scan

    with connect() as conn:
        run_azure_scan(
            tenant, TENANT, SUBSCRIPTION, AzureClient(opener=fake_opener()), conn=conn
        )
        rows = conn.execute(
            "SELECT natural_key FROM findings WHERE tenant_id = %s "
            "AND finding_type = 'orphaned_credential'",
            (tenant,),
        ).fetchall()
    assert any("cert-1" in str(row[0]) for row in rows)


@requires_pg
def test_no_secret_value_reaches_the_database(tenant) -> None:
    from abx_scanner.db import connect
    from abx_scanner.scan import run_azure_scan

    with connect() as conn:
        run_azure_scan(
            tenant, TENANT, SUBSCRIPTION, AzureClient(opener=fake_opener()), conn=conn
        )
        fingerprints = [
            row[0] for row in conn.execute(
                "SELECT fingerprint FROM credentials WHERE tenant_id = %s", (tenant,)
            ).fetchall()
        ]
    assert fingerprints
    assert all(value.startswith("azkey:") for value in fingerprints)
