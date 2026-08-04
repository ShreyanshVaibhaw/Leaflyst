"""Every route against every credential kind (plansecurity SP-3).

The gate asks for a matrix over all documented methods rather than a sample,
because the routes that get hand-written tests are the ones someone was already
thinking about, and the ones that slip are the ones nobody remembered. Both
guard defects found on August 2 were on routes that had tests.

So this walks the checked-in route-guards table instead of a hand-maintained
list. A new route lands in the matrix the moment it lands in the table, and the
route-guard test already fails the build if a route is missing from the table.
That closure is the point: there is no way to add a route that neither file
notices.

Three axes are covered here, each answering a different question:

    no credential          is the route guarded at all?
    wrong credential kind  can one kind of token stand in for another?
    wrong tenant           can a bound token reach across the boundary?

Object-level behaviour that needs real rows - a revoked share token, an
evidence export for a tenant with no events - lives in the suites that own
those features. This file is about the boundary, not the payload.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import psycopg
import pytest
from abx_api.main import app
from abx_api.route_guards import TABLE_PATH
from abx_api.settings import settings
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-Abx-Admin-Key": "dev-admin-key"}
SAMPLE_UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

GUARDS: dict[str, str] = json.loads(Path(TABLE_PATH).read_text(encoding="utf-8"))

#: Routes that answer without a credential by design. The share route is the
#: interesting one: its token IS the credential, so an unguarded GET is correct
#: and the protection lives in the token being unguessable and revocable.
PUBLIC_ROUTES = {entry for entry, guard in GUARDS.items() if guard == "public"}
GUARDED_ROUTES = sorted(set(GUARDS) - PUBLIC_ROUTES)

#: Guard labels that accept a capability token (admin key or scoped read token)
#: rather than a write-only ingest or scan-upload token.
CAPABILITY_GUARDS = {"read", "export_evidence", "revoke", "triage", "configure"}


def fill(path: str) -> str:
    """Substitute path parameters with syntactically valid values.

    Deliberately valid rather than junk: a malformed identifier is rejected by
    the identifier boundary (SEC-B07) and would mask whether the auth check ran
    at all. This file tests authentication, so every request must be well formed
    enough to reach it.
    """
    filled = path
    for name in ("credential_id", "finding_id", "agent_id", "alert_id", "token_id"):
        filled = filled.replace("{" + name + "}", SAMPLE_UUID)
    filled = filled.replace("{session_id}", "sess-matrix-probe")
    filled = filled.replace("{token}", "abx_share_matrix_probe")
    filled = filled.replace("{kind}", "ingest")
    return filled


def send(client: TestClient, entry: str, tenant_id: str, headers: dict[str, str]):
    method, path = entry.split(" ", 1)
    body = {} if method in {"POST", "PUT", "PATCH"} else None
    return client.request(
        method, fill(path), params={"tenant_id": tenant_id}, headers=headers, json=body
    )


@pytest.fixture(scope="module")
def two_tenants():
    """Tenants A and B, each with its own capability and write-only tokens.

    Setup and yield sit inside a try/finally because the tenant rows commit
    before the tokens are minted. Without it, a failure between those two points
    means the fixture never reaches yield, pytest never runs teardown, and the
    tenants leak - taking their payload segments with them and breaking the
    global key-rotation drill in a later file for reasons that look unrelated.
    """
    from abx_api.auth import new_ingest_token, new_scan_token

    made: list[str] = []
    tokens: dict[str, dict[str, str]] = {}
    try:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
            for label in ("a", "b"):
                row = conn.execute(
                    "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
                    (f"matrix-{label}-{uuid.uuid4().hex[:8]}",),
                ).fetchone()
                assert row is not None
                tenant_id = str(row[0])
                made.append(tenant_id)
                ingest, ingest_hash = new_ingest_token()
                conn.execute(
                    "INSERT INTO ingest_tokens (tenant_id, token_hash, label) "
                    "VALUES (%s,%s,'matrix')",
                    (tenant_id, ingest_hash),
                )
                scan, scan_hash = new_scan_token()
                conn.execute(
                    "INSERT INTO scan_upload_tokens (tenant_id, token_hash, label) "
                    "VALUES (%s,%s,'matrix')",
                    (tenant_id, scan_hash),
                )
                tokens[label] = {"tenant_id": tenant_id, "ingest": ingest, "scan": scan}

        client = TestClient(app)
        for label in ("a", "b"):
            for role in ("viewer", "admin"):
                response = client.post(
                    f"/v1/settings/read-tokens?tenant_id={tokens[label]['tenant_id']}",
                    json={"label": f"matrix-{role}", "role": role},
                    headers=ADMIN,
                )
                assert response.status_code == 200, response.text
                tokens[label][role] = response.json()["token"]

        yield tokens
    finally:
        # _delete_tenant_data is imported at module scope, not here. Two test
        # trees ship a file called conftest.py, so a deferred import inside
        # teardown can resolve to services/scanner's copy instead of this one,
        # and the resulting ImportError leaks both tenants along with their
        # payload segments.
        with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
            for tenant_id in made:
                _delete_tenant_data(conn, tenant_id)
                conn.execute("DELETE FROM read_tokens WHERE tenant_id = %s", (tenant_id,))
                conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))


@requires_stack
@pytest.mark.parametrize("entry", GUARDED_ROUTES)
def test_no_credential_is_refused(entry: str) -> None:
    """401 rather than 422: an unauthenticated caller learns nothing about the body.

    A route that validates its payload before checking the credential tells an
    anonymous caller the shape of its schema, and tells them which routes exist
    by answering differently for a well-formed body than a malformed one.
    """
    response = send(TestClient(app, raise_server_exceptions=False), entry, SAMPLE_UUID, {})
    assert response.status_code == 401, (entry, response.status_code, response.text[:200])


@requires_stack
@pytest.mark.parametrize("entry", GUARDED_ROUTES)
def test_a_malformed_credential_is_refused(entry: str) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    for headers in (
        {"Authorization": "Bearer not-a-real-token"},
        {"Authorization": "Bearer abx_read_forged_value_that_never_existed"},
        {"X-Abx-Admin-Key": "wrong-admin-key"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},
    ):
        response = send(client, entry, SAMPLE_UUID, headers)
        assert response.status_code == 401, (entry, headers, response.status_code)


@requires_stack
@pytest.mark.parametrize(
    "entry", sorted(e for e in GUARDED_ROUTES if GUARDS[e] in CAPABILITY_GUARDS)
)
def test_a_write_only_ingest_token_cannot_read(entry: str, two_tenants) -> None:
    """The recording plane's token is write-only, and must not open a read route.

    This is the inverse of the August 2 policy defect. That one let a read token
    write to the chain; this asserts the other direction stays shut, so the two
    credential kinds cannot substitute for each other in either direction.
    """
    client = TestClient(app, raise_server_exceptions=False)
    tenant = two_tenants["a"]
    response = send(
        client, entry, tenant["tenant_id"], {"Authorization": f"Bearer {tenant['ingest']}"}
    )
    assert response.status_code == 401, (entry, response.status_code, response.text[:200])


@requires_stack
@pytest.mark.parametrize(
    "entry", sorted(e for e in GUARDED_ROUTES if GUARDS[e] == "ingest-token")
)
def test_a_capability_token_cannot_reach_the_recording_plane(entry: str, two_tenants) -> None:
    """An admin read token is not an ingest token, however privileged it is."""
    client = TestClient(app, raise_server_exceptions=False)
    tenant = two_tenants["a"]
    for headers in (
        {"Authorization": f"Bearer {tenant['admin']}"},
        ADMIN,
    ):
        response = send(client, entry, tenant["tenant_id"], headers)
        assert response.status_code == 401, (entry, headers, response.status_code)


@requires_stack
@pytest.mark.parametrize(
    "entry", sorted(e for e in GUARDED_ROUTES if GUARDS[e] in CAPABILITY_GUARDS)
)
def test_a_bound_token_cannot_reach_another_tenant(entry: str, two_tenants) -> None:
    """A real other tenant must be indistinguishable from one that never existed.

    Asserting only "404 for the other tenant" is the obvious version of this test
    and it is close to worthless: 12 of these routes answer 404 on their OWN
    tenant too, because the object being asked for does not exist. On those the
    assertion passes whether isolation works or not.

    Comparing against a randomly generated tenant id is the property that
    actually matters and that holds on every route. If any route distinguishes
    "exists but is not yours" from "does not exist", a caller with one valid
    token can enumerate tenants by status code alone, without reading any data.
    """
    client = TestClient(app, raise_server_exceptions=False)
    a, b = two_tenants["a"], two_tenants["b"]
    headers = {"Authorization": f"Bearer {a['admin']}"}

    other = send(client, entry, b["tenant_id"], headers)
    phantom = send(client, entry, str(uuid.uuid4()), headers)

    assert other.status_code == phantom.status_code, (
        entry, "existence oracle", other.status_code, phantom.status_code
    )
    assert other.text == phantom.text, (entry, "response differs by tenant existence")
    assert other.status_code == 404, (entry, other.status_code, other.text[:200])
    assert b["tenant_id"] not in other.text


@requires_stack
def test_an_unknown_tenant_is_indistinguishable_from_another_tenant(two_tenants) -> None:
    """The existence oracle, stated directly rather than per route."""
    client = TestClient(app, raise_server_exceptions=False)
    a, b = two_tenants["a"], two_tenants["b"]
    headers = {"Authorization": f"Bearer {a['admin']}"}
    entry = "GET /v1/dashboard/overview"
    real_other = send(client, entry, b["tenant_id"], headers)
    never_existed = send(client, entry, str(uuid.uuid4()), headers)
    assert real_other.status_code == never_existed.status_code == 404
    assert real_other.json() == never_existed.json()


@requires_stack
def test_the_matrix_covers_every_documented_route() -> None:
    """The gate asks for 100% of documented methods, so prove the count."""
    spec = json.loads((TABLE_PATH.parent / "openapi.json").read_text(encoding="utf-8"))
    documented = {
        f"{method.upper()} {path}"
        for path, operations in spec["paths"].items()
        for method in operations
    }
    uncovered = documented - set(GUARDS)
    assert not uncovered, f"routes absent from the auth matrix: {sorted(uncovered)}"
    assert len(GUARDED_ROUTES) + len(PUBLIC_ROUTES) == len(GUARDS)


# -- scan-upload token, the third credential kind ------------------------------

SCAN_ROUTES = sorted(e for e in GUARDED_ROUTES if GUARDS[e] == "scan-upload-token")


@requires_stack
@pytest.mark.parametrize("entry", SCAN_ROUTES)
def test_only_a_scan_upload_token_opens_the_scan_upload_route(
    entry: str, two_tenants
) -> None:
    """Three credential kinds exist, so the matrix needs all three.

    The scanner's token is write-only and single-purpose: it uploads findings.
    An ingest token, a capability token, and the operator key must all be
    refused here, or the separation between the scan plane and the recording
    plane is a naming convention rather than a control.
    """
    client = TestClient(app, raise_server_exceptions=False)
    tenant = two_tenants["a"]
    for label, headers in (
        ("ingest", {"Authorization": f"Bearer {tenant['ingest']}"}),
        ("read-admin", {"Authorization": f"Bearer {tenant['admin']}"}),
        ("operator-key", ADMIN),
        ("none", {}),
    ):
        response = send(client, entry, tenant["tenant_id"], headers)
        assert response.status_code == 401, (entry, label, response.status_code)


@requires_stack
@pytest.mark.parametrize(
    "entry",
    sorted(
        e
        for e in GUARDED_ROUTES
        if GUARDS[e] in CAPABILITY_GUARDS or GUARDS[e] == "ingest-token"
    ),
)
def test_a_scan_upload_token_opens_nothing_else(entry: str, two_tenants) -> None:
    """The inverse direction: the scanner's credential is not a skeleton key."""
    client = TestClient(app, raise_server_exceptions=False)
    tenant = two_tenants["a"]
    response = send(
        client, entry, tenant["tenant_id"], {"Authorization": f"Bearer {tenant['scan']}"}
    )
    assert response.status_code == 401, (entry, response.status_code, response.text[:200])


@requires_stack
@pytest.mark.parametrize("entry", SCAN_ROUTES)
def test_a_scan_upload_token_is_bound_to_its_own_tenant(entry: str, two_tenants) -> None:
    """Tenant comes from the token, so naming another tenant must not redirect it."""
    client = TestClient(app, raise_server_exceptions=False)
    a, b = two_tenants["a"], two_tenants["b"]
    response = send(
        client, entry, b["tenant_id"], {"Authorization": f"Bearer {a['scan']}"}
    )
    assert response.status_code < 500, (entry, response.status_code)
    assert b["tenant_id"] not in response.text
