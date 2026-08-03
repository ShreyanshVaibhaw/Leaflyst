"""Edge boundary: forwarded-header trust, layered rate limits, demo budgets.

Covers plansecurity SP-2's application-layer half. TLS termination, port
exposure, and the proxy itself are host concerns and are proven on the node.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

import pytest
from abx_api import rate_limit
from abx_api.demo import purge_expired_public_demos
from abx_api.main import app
from abx_api.rate_limit import caller_identity, client_address
from abx_api.settings import settings
from conftest import requires_stack
from fastapi.testclient import TestClient


def scope(client_host: str, headers: dict[str, str] | None = None, path: str = "/v1/x") -> dict:
    return {
        "type": "http",
        "path": path,
        "client": (client_host, 51234),
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }


def test_a_forwarded_header_from_an_untrusted_peer_is_ignored(monkeypatch) -> None:
    """With no proxy declared, X-Forwarded-For is attacker-supplied text."""
    monkeypatch.setattr(rate_limit, "settings", replace(settings, trusted_proxy_hops=0))
    spoofed = scope("203.0.113.9", {"X-Forwarded-For": "1.2.3.4"})
    assert client_address(spoofed) == "203.0.113.9"


def test_one_trusted_hop_reads_the_address_that_proxy_appended(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit, "settings", replace(settings, trusted_proxy_hops=1))
    forwarded = scope("10.0.0.2", {"X-Forwarded-For": "198.51.100.7"})
    assert client_address(forwarded) == "198.51.100.7"


def test_a_client_cannot_prepend_its_way_to_a_different_identity(monkeypatch) -> None:
    """The classic bypass: send your own XFF so the real value moves left."""
    monkeypatch.setattr(rate_limit, "settings", replace(settings, trusted_proxy_hops=1))
    # The proxy appends the true client, so the rightmost entry is the only one
    # it wrote. Everything the caller injected sits to the left of it.
    injected = scope("10.0.0.2", {"X-Forwarded-For": "9.9.9.9, 198.51.100.7"})
    assert client_address(injected) == "198.51.100.7"


def test_a_short_forwarded_chain_falls_back_to_the_peer(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit, "settings", replace(settings, trusted_proxy_hops=2))
    assert client_address(scope("10.0.0.2", {"X-Forwarded-For": "1.1.1.1"})) == "10.0.0.2"


def test_a_credential_identifies_the_caller_and_is_never_stored_raw() -> None:
    token = "abx_ingest_super_secret_value"
    identity = caller_identity(scope("10.0.0.9", {"Authorization": f"Bearer {token}"}))
    assert identity.startswith("tok:")
    assert token not in identity
    assert len(identity) == len("tok:") + 16
    # Two callers from one address are still two callers.
    other = caller_identity(scope("10.0.0.9", {"Authorization": "Bearer different"}))
    assert other != identity
    # And no credential means the address is what gets charged.
    assert caller_identity(scope("10.0.0.9")) == "ip:10.0.0.9"


@requires_stack
def test_the_caller_limit_returns_429_with_retry_after(monkeypatch) -> None:
    monkeypatch.setattr(
        rate_limit,
        "settings",
        replace(settings, rate_limit_enabled=True, rate_limit_requests=3),
    )
    client = TestClient(app)
    token = f"Bearer probe-{uuid.uuid4()}"
    codes = [
        client.get("/v1/chain/verify", headers={"Authorization": token}).status_code
        for _ in range(6)
    ]
    assert 429 in codes, codes
    limited = client.get("/v1/chain/verify", headers={"Authorization": token})
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0


@requires_stack
def test_health_checks_are_never_rate_limited(monkeypatch) -> None:
    """A limiter that can black out liveness probes takes the service down itself."""
    monkeypatch.setattr(
        rate_limit,
        "settings",
        replace(settings, rate_limit_enabled=True, rate_limit_requests=1),
    )
    client = TestClient(app)
    assert {client.get("/healthz").status_code for _ in range(5)} == {200}


@requires_stack
def test_the_limiter_allows_traffic_when_redis_is_unreachable(monkeypatch) -> None:
    """Recording degrades, the agent keeps working - never the reverse."""

    def broken() -> None:
        raise ConnectionError("redis is down")

    monkeypatch.setattr(rate_limit, "redis_client", broken)
    monkeypatch.setattr(
        rate_limit,
        "settings",
        replace(settings, rate_limit_enabled=True, rate_limit_requests=1),
    )
    client = TestClient(app)
    assert client.get("/v1/chain/verify").status_code != 429


@requires_stack
def test_rotating_the_visitor_cookie_cannot_outrun_the_global_demo_budget(monkeypatch) -> None:
    """The per-visitor limit is keyed on a value the visitor picks. This is not."""
    monkeypatch.setattr(
        "abx_api.demo.settings",
        replace(
            settings,
            demo_enabled=True,
            public_demo_max_runs_per_hour=5,
            public_demo_max_runs_per_hour_global=0,
            public_demo_ttl_hours=1,
        ),
    )
    client = TestClient(app)
    refused = client.post(
        "/v1/demo/public/run",
        json={"visitor_ref": uuid.uuid4().hex * 2},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert refused.status_code == 429
    assert "budget" in refused.json()["detail"]


@requires_stack
def test_a_full_sandbox_pool_refuses_new_visitors_rather_than_growing(monkeypatch) -> None:
    monkeypatch.setattr(
        "abx_api.demo.settings",
        replace(
            settings,
            demo_enabled=True,
            public_demo_max_runs_per_hour=5,
            public_demo_max_live_tenants=0,
            public_demo_ttl_hours=1,
        ),
    )
    refused = TestClient(app).post(
        "/v1/demo/public/run",
        json={"visitor_ref": uuid.uuid4().hex * 2},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert refused.status_code == 429
    assert "free sandbox" in refused.json()["detail"]


@requires_stack
def test_expired_sandboxes_are_reclaimed_so_the_cap_is_a_limit_not_a_wall() -> None:
    """Without reclamation the live cap would eventually close the demo forever."""
    import psycopg
    from abx_api.settings import settings as live

    visitor = uuid.uuid4().hex * 2
    with psycopg.connect(live.pg_dsn, autocommit=True) as conn:
        tenant = conn.execute(
            "INSERT INTO tenants (name) VALUES ('expired sandbox probe') RETURNING id"
        ).fetchone()
        assert tenant is not None
        conn.execute(
            "INSERT INTO public_demo_tenants (visitor_ref,demo_tenant_id,runs_in_window,"
            "expires_at) VALUES (%s,%s,1,now() - interval '1 hour')",
            (visitor, tenant[0]),
        )
        try:
            assert purge_expired_public_demos() >= 1
            remaining = conn.execute(
                "SELECT count(*) FROM public_demo_tenants WHERE visitor_ref=%s", (visitor,)
            ).fetchone()
            assert remaining is not None and remaining[0] == 0
        finally:
            conn.execute("DELETE FROM public_demo_tenants WHERE visitor_ref=%s", (visitor,))
            conn.execute("DELETE FROM tenants WHERE id=%s", (tenant[0],))


@pytest.mark.parametrize(
    "path",
    ["/v1/compliance/pack", "/v1/evidence/tenant", "/v1/reports/sessions/x", "/v1/demo/run"],
)
def test_expensive_routes_carry_their_own_lower_limit(path: str) -> None:
    assert any(marker in path for marker in rate_limit.COSTLY_MARKERS), path
