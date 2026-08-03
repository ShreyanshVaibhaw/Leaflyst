"""The guard every route actually resolves to, read off the built application.

The July 31 isolation audit and the August 2 baseline both found a mutating
route sitting behind a read-only capability, and both times the mistake was
invisible at the call site: the router had been moved to a new guard wholesale,
or the guard hid behind a module alias whose name no longer described its value.
Reading the name a guard was bound under cannot catch that. Reading what the
built dependency graph resolves to can.

The inventory is compared against a checked-in table so that adding a route is a
visible diff rather than a silent expansion of the attack surface, and so that
changing an existing route's guard has to be argued for in review.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute

from abx_api.rbac import Capability

TABLE_PATH = Path(__file__).resolve().parents[2] / "route-guards.json"

#: Capabilities that grant no authority to change anything. A route that is not
#: GET or HEAD must never resolve to one of these. EXPORT_EVIDENCE belongs here
#: because it is what an external assessor holds, and an assessor who can alter
#: state undermines the independence of their own assessment.
READ_ONLY_CAPABILITIES = frozenset({Capability.READ, Capability.EXPORT_EVIDENCE})

PUBLIC = "public"
UNGUARDED_METHODS = frozenset({"HEAD", "OPTIONS"})

#: Non-capability credentials, named by the dependency that enforces them.
_TOKEN_GUARDS = {
    "ingest_identity_from_token": "ingest-token",
    "tenant_from_scan_token": "scan-upload-token",
}


def _guards_of(dependant: Any, seen: set[int]) -> set[str]:
    """Every guard reachable from one route's dependency graph."""
    found: set[str] = set()
    call = getattr(dependant, "call", None)
    if call is not None:
        capability = getattr(call, "abx_capability", None)
        if capability is not None:
            found.add(str(capability.value))
        name = getattr(call, "__name__", "")
        if name in _TOKEN_GUARDS:
            found.add(_TOKEN_GUARDS[name])
    for sub in getattr(dependant, "dependencies", ()):
        if id(sub) in seen:
            continue
        seen.add(id(sub))
        found |= _guards_of(sub, seen)
    return found


def _declared_guards(dependencies: Any) -> set[str]:
    """Guards from a router-level ``dependencies=[Depends(...)]`` list."""
    found: set[str] = set()
    for declared in dependencies or ():
        call = getattr(declared, "dependency", None)
        capability = getattr(call, "abx_capability", None)
        if capability is not None:
            found.add(str(capability.value))
        name = getattr(call, "__name__", "")
        if name in _TOKEN_GUARDS:
            found.add(_TOKEN_GUARDS[name])
    return found


def _collect(routes: Any, prefix: str, inherited: set[str], into: dict[str, str]) -> None:
    """Walk routers depth-first, carrying prefixes and inherited guards down.

    FastAPI defers router inclusion rather than flattening it, so a route's own
    dependency graph does not necessarily contain the guards its router declared.
    Missing those is precisely how a mutating route can look guarded when it is
    not, so inherited guards are threaded through the walk explicitly.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            guards = inherited | _guards_of(route.dependant, set())
            label = "+".join(sorted(guards)) if guards else PUBLIC
            for method in sorted(route.methods or ()):
                if method in UNGUARDED_METHODS:
                    continue
                into[f"{method} {prefix}{route.path}"] = label
            continue
        router = getattr(route, "original_router", None)
        if router is None:
            continue
        context = getattr(route, "include_context", None)
        nested = (
            inherited
            | _declared_guards(getattr(context, "dependencies", ()))
            | _declared_guards(getattr(router, "dependencies", ()))
        )
        # Only the include-time prefix is added: a router's own prefix is already
        # baked into each route's path when the route is declared.
        _collect(router.routes, prefix + str(getattr(context, "prefix", "") or ""), nested, into)


def route_guard_inventory(app: FastAPI) -> dict[str, str]:
    """Map ``"METHOD /path"`` to the guard the route resolves to.

    A route with several guards is reported as all of them joined by ``+``, so a
    route that gains a second credential requirement shows up as a changed entry
    rather than being silently reduced to one of them.
    """
    inventory: dict[str, str] = {}
    _collect(app.routes, "", set(), inventory)
    return dict(sorted(inventory.items()))


def mutating_read_only_routes(inventory: dict[str, str]) -> list[str]:
    """Routes that change state while resolving only to a read-only capability."""
    offenders = []
    for entry, guard in inventory.items():
        method = entry.split(" ", 1)[0]
        if method in {"GET", "HEAD", "OPTIONS"}:
            continue
        parts = set(guard.split("+"))
        if parts and parts <= {capability.value for capability in READ_ONLY_CAPABILITIES}:
            offenders.append(entry)
    return offenders


def _render(inventory: dict[str, str]) -> str:
    return json.dumps(inventory, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":  # pragma: no cover - developer regeneration entry point
    from abx_api.main import app

    TABLE_PATH.write_text(_render(route_guard_inventory(app)), encoding="utf-8")
    print(f"wrote {TABLE_PATH}")
