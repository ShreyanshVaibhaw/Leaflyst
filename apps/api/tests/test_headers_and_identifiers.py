"""Response hardening and identifier validation (SEC-B06, SEC-B07).

B07 as recorded said "malformed tenant input can produce a sanitized HTTP 500".
Reproducing it showed the same fault on every object identifier too, so the
tests below cover both, and cover them across routers rather than on the one
endpoint the finding happened to name.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from abx_api.identifiers import is_uuid
from abx_api.main import app
from abx_api.security_headers import BASE_HEADERS, interactive_docs_enabled
from abx_api.settings import settings
from conftest import requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}

MALFORMED = [
    "not-a-uuid",
    "",
    "'; DROP TABLE tenants;--",
    "00000000-0000-0000-0000-00000000000Z",
    "../../etc/passwd",
    "%00",
    "1 OR 1=1",
]

TENANT_ROUTES = [
    "/v1/dashboard/overview",
    "/v1/dashboard/findings",
    "/v1/dashboard/credentials",
    "/v1/replay/agents",
    "/v1/chain/verify",
    "/v1/alerts",
    "/v1/settings",
    "/v1/policy",
]

OBJECT_ROUTES = [
    "/v1/dashboard/credentials/{id}",
    "/v1/dashboard/findings/{id}",
    "/v1/replay/agents/{id}/sessions",
    "/v1/replay/credentials/{id}/events",
    "/v1/revocation/{id}/impact",
]


@requires_stack
@pytest.mark.parametrize("path", TENANT_ROUTES)
def test_a_malformed_tenant_is_a_client_error_not_a_server_error(path: str) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    for probe in MALFORMED:
        response = client.get(path, params={"tenant_id": probe}, headers=ADMIN)
        assert response.status_code == 400, (path, probe, response.status_code)
        assert response.json()["detail"] == "tenant_id must be a UUID"


@requires_stack
@pytest.mark.parametrize("path", OBJECT_ROUTES)
def test_a_malformed_object_id_is_rejected_before_the_database(path: str, tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app, raise_server_exceptions=False)
    probes = ("not-a-uuid", "1 OR 1=1", "%27%20OR%201%3D1", "00000000-0000-0000-0000-0000000000zz")
    for probe in probes:
        response = client.get(
            path.format(id=probe), params={"tenant_id": tenant_id}, headers=ADMIN
        )
        assert response.status_code == 422, (path, probe, response.status_code)
    # A traversal attempt does not reach the route at all, because the extra
    # separators make it a different path. 404 is the right answer there; what
    # matters is that no probe reaches the database.
    traversal = client.get(
        path.format(id="../../etc/passwd"), params={"tenant_id": tenant_id}, headers=ADMIN
    )
    assert traversal.status_code == 404, (path, traversal.status_code)


@requires_stack
def test_a_rejected_identifier_leaks_nothing_about_the_database(tenant) -> None:
    """A 500 here would have told the caller their input reached the query."""
    tenant_id, _ = tenant
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get(
        "/v1/dashboard/credentials/not-a-uuid", params={"tenant_id": tenant_id}, headers=ADMIN
    )
    body = response.text.lower()
    for leak in ("psycopg", "select ", "traceback", "invalidtextrepresentation", "line "):
        assert leak not in body, leak


def test_valid_uuids_are_accepted_and_nothing_else_is() -> None:
    """The negative control: a validator that accepts everything proves nothing."""
    assert is_uuid("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    assert is_uuid("3F2504E0-4F89-11D3-9A0C-0305E82C3301")
    assert not is_uuid("3f2504e0-4f89-11d3-9a0c-0305e82c330")
    assert not is_uuid("3f2504e0-4f89-11d3-9a0c-0305e82c3301x")
    assert not is_uuid("3f2504e04f8911d39a0c0305e82c3301")
    assert not is_uuid("")


@requires_stack
def test_every_response_carries_the_hardening_headers() -> None:
    response = TestClient(app).get("/healthz")
    for name, value in BASE_HEADERS:
        assert response.headers[name.decode()] == value.decode()
    assert "server" not in {key.lower() for key in response.headers}


@requires_stack
def test_rejected_requests_are_hardened_too() -> None:
    """A 4xx is still a response an attacker's browser will parse."""
    client = TestClient(app, raise_server_exceptions=False)
    for response in (
        client.get("/v1/dashboard/overview", params={"tenant_id": "bad"}, headers=ADMIN),
        client.get("/v1/dashboard/overview"),
        client.get("/v1/no-such-route"),
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["content-security-policy"].startswith("default-src 'none'")


def test_hsts_is_sent_only_where_https_is_required(monkeypatch) -> None:
    """Pinning a browser to a scheme the deployment cannot serve is an outage."""
    from abx_api import security_headers

    monkeypatch.setattr(security_headers, "settings", replace(settings, require_https=False))
    assert security_headers.HSTS not in security_headers.SecurityHeaders(None).headers
    monkeypatch.setattr(security_headers, "settings", replace(settings, require_https=True))
    assert security_headers.HSTS in security_headers.SecurityHeaders(None).headers


def test_interactive_docs_are_off_in_production() -> None:
    """The docs publish the route inventory and issue live requests from a form."""
    assert interactive_docs_enabled("development")
    assert interactive_docs_enabled("staging")
    assert not interactive_docs_enabled("production")


def test_the_application_wires_the_docs_decision_rather_than_hardcoding_it() -> None:
    """The helper above is only worth testing if the app actually consults it."""
    expected = interactive_docs_enabled(settings.environment)
    assert (app.docs_url is not None) is expected
    assert (app.redoc_url is not None) is expected
    assert (app.openapi_url is not None) is expected


@requires_stack
def test_docs_remain_available_outside_production() -> None:
    client = TestClient(app)
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
