"""The standing route-guard inventory (plansecurity SP-8).

Twice now a mutating route has shipped behind a read-only capability, and both
times a human reading the call site saw nothing wrong. This is the check that
does not depend on anyone reading carefully.
"""

from __future__ import annotations

import json

from abx_api.main import app
from abx_api.rbac import require_configure, require_read
from abx_api.route_guards import (
    TABLE_PATH,
    mutating_read_only_routes,
    route_guard_inventory,
)
from fastapi import APIRouter, Depends, FastAPI

REGENERATE = "uv run python -m abx_api.route_guards"


def test_the_guard_table_matches_the_application() -> None:
    """Adding or re-guarding a route has to be an explicit, reviewable diff."""
    expected = json.loads(TABLE_PATH.read_text(encoding="utf-8"))
    actual = route_guard_inventory(app)

    added = {route: actual[route] for route in actual.keys() - expected.keys()}
    removed = sorted(expected.keys() - actual.keys())
    changed = {
        route: f"{expected[route]} -> {actual[route]}"
        for route in expected.keys() & actual.keys()
        if expected[route] != actual[route]
    }
    assert not added, f"new unguarded-by-review routes: {added}. Run `{REGENERATE}`"
    assert not removed, f"routes disappeared: {removed}. Run `{REGENERATE}`"
    assert not changed, f"guards changed: {changed}. Run `{REGENERATE}` and justify in review"


def test_no_mutating_route_resolves_to_a_read_only_capability() -> None:
    assert mutating_read_only_routes(route_guard_inventory(app)) == []


def test_the_check_catches_a_deliberately_mis_guarded_route() -> None:
    """A negative control: the check is worthless if it cannot fail."""
    router = APIRouter(prefix="/trap", dependencies=[Depends(require_read)])

    @router.post("/mutate")
    def mutate() -> dict[str, str]:
        return {}

    @router.get("/look")
    def look() -> dict[str, str]:
        return {}

    trap = FastAPI()
    trap.include_router(router)

    inventory = route_guard_inventory(trap)
    assert inventory["POST /trap/mutate"] == "read"
    assert mutating_read_only_routes(inventory) == ["POST /trap/mutate"]
    # ...and passes once the same route is guarded properly.
    assert mutating_read_only_routes({"POST /trap/mutate": "configure"}) == []


def test_router_level_guards_are_seen_through_deferred_inclusion() -> None:
    """FastAPI does not flatten included routers, so the walk must not either."""
    router = APIRouter(prefix="/nested", dependencies=[Depends(require_configure)])

    @router.post("/thing")
    def thing() -> dict[str, str]:
        return {}

    outer = APIRouter(prefix="/outer")
    outer.include_router(router)
    application = FastAPI()
    application.include_router(outer)

    inventory = route_guard_inventory(application)
    assert inventory == {"POST /outer/nested/thing": "configure"}


def test_every_documented_route_is_in_the_table() -> None:
    """The table may cover more than OpenAPI does, never less.

    Routes hidden from the schema still accept traffic, so a guard inventory
    built from the published document alone would miss exactly the routes an
    attacker has to discover rather than read.
    """
    spec = json.loads((TABLE_PATH.parent / "openapi.json").read_text(encoding="utf-8"))
    documented = {
        f"{method.upper()} {path}"
        for path, operations in spec["paths"].items()
        for method in operations
    }
    assert documented <= set(json.loads(TABLE_PATH.read_text(encoding="utf-8")))


def test_the_checked_in_openapi_document_still_matches_the_application() -> None:
    """SP-6b asks that the matrix be regenerated against the CURRENT document.

    Nothing regenerated `openapi.json`, so it could drift from the app while
    every test that reads it kept passing. The drift is quiet in the dangerous
    direction: two tests assert "every DOCUMENTED route is covered", and a route
    missing from a stale document is a route those assertions stop asking about.

    The guard table itself is pinned to the live app, so this is a second lock
    on the same door rather than the only one - but it is the lock the gate
    names, and a stale published contract is its own problem for anyone
    generating a client from it.
    """
    from abx_api.main import app

    live = {
        f"{method.upper()} {path}"
        for path, operations in app.openapi()["paths"].items()
        for method in operations
    }
    on_disk = {
        f"{method.upper()} {path}"
        for path, operations in json.loads(
            (TABLE_PATH.parent / "openapi.json").read_text(encoding="utf-8")
        )["paths"].items()
        for method in operations
    }
    assert live == on_disk, (
        f"openapi.json is stale; regenerate it. "
        f"only in the app: {sorted(live - on_disk)}; "
        f"only in the document: {sorted(on_disk - live)}"
    )
