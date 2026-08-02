"""Tool definition history, rug-pull detection, and inventory confidence.

Blueprint2 14.4. Leaflyst's structural advantage here is that a per-client,
per-session history of tool definitions across time is not available to
anything with a gateway-only view.

Two sources, deliberately:

- resource_refs carry `abx:tool-def:<name>:<digest>` for every tool. They are
  inside the hashed event and always stored, so DETECTION works even when
  payload capture is off.
- The payload carries the raw tools/list response, which is what supplies the
  description text for the poisoning heuristic and the before/after diff.

That split is why detection degrades to "we know which tool changed" rather
than to nothing when a tenant disables payload capture.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from abx_rules import poison_matches
from psycopg import Connection

TOOL_DEF_PREFIX = "abx:tool-def:"
INVENTORY_PREFIX = "abx:tool-inventory:"
TTL_PREFIX = "abx:tool-cache-ttl-ms:"
SCOPE_PREFIX = "abx:tool-cache-scope:"


def parse_tool_refs(refs: list[str]) -> dict[str, str]:
    """`{tool_name: digest}` from an event's resource_refs."""
    tools: dict[str, str] = {}
    for ref in refs:
        if not ref.startswith(TOOL_DEF_PREFIX):
            continue
        name, _, digest = ref.removeprefix(TOOL_DEF_PREFIX).rpartition(":")
        if name and digest:
            tools[name] = digest
    return tools


def _hint(refs: list[str], prefix: str) -> str | None:
    return next((r.removeprefix(prefix) for r in refs if r.startswith(prefix)), None)


def tool_descriptions(payload: str | None) -> dict[str, str]:
    """`{tool_name: description}` from a captured tools/list payload.

    Returns {} when payload capture is off or the body is unparseable; the
    caller must treat that as "unknown", never as "clean".
    """
    if not payload:
        return {}
    try:
        wrapper = json.loads(payload)
        raw = json.loads(wrapper["raw"]) if isinstance(wrapper, dict) else None
        tools = raw.get("result", {}).get("tools", []) if isinstance(raw, dict) else []
    except (ValueError, KeyError, TypeError, AttributeError):
        return {}
    return {
        t["name"]: t.get("description", "")
        for t in tools
        if isinstance(t, dict) and isinstance(t.get("name"), str)
    }


def record_and_diff(
    conn: Connection,
    tenant_id: str,
    server_name: str,
    session_id: str,
    refs: list[str],
    payload: str | None,
) -> tuple[
    tuple[tuple[str, float, int], ...],
    tuple[tuple[str, tuple[str, ...]], ...],
]:
    """Record observed definitions; return (changed_tools, poisoned_tools).

    changed_tools carries the trust window - days and distinct sessions the
    previous definition was live - because that window is what separates a
    server publishing its tools from a rug pull.
    """
    observed = parse_tool_refs(refs)
    if not observed:
        return (), ()
    descriptions = tool_descriptions(payload)
    now = datetime.now(UTC)
    changed: list[tuple[str, float, int]] = []

    for name, digest in observed.items():
        prior = conn.execute(
            "SELECT definition_hash,first_seen,sessions_seen FROM tool_definitions "
            "WHERE tenant_id=%s AND server_name=%s AND tool_name=%s "
            "AND superseded_at IS NULL ORDER BY first_seen DESC LIMIT 1",
            (tenant_id, server_name, name),
        ).fetchone()

        if prior is not None and str(prior[0]) != digest:
            first_seen = prior[1]
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=UTC)
            changed.append((
                name,
                (now - first_seen).total_seconds() / 86400,
                int(prior[2]),
            ))
            conn.execute(
                "UPDATE tool_definitions SET superseded_at=now() WHERE tenant_id=%s "
                "AND server_name=%s AND tool_name=%s AND superseded_at IS NULL",
                (tenant_id, server_name, name),
            )

        conn.execute(
            "INSERT INTO tool_definitions "
            "(tenant_id,server_name,tool_name,definition_hash,definition_text) "
            "VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (tenant_id,server_name,tool_name,definition_hash) "
            "DO UPDATE SET last_seen=now(), superseded_at=NULL, "
            "sessions_seen=tool_definitions.sessions_seen+"
            "  CASE WHEN tool_definitions.last_seen < now() - INTERVAL '1 second'"
            "  THEN 1 ELSE 0 END",
            (tenant_id, server_name, name, digest, descriptions.get(name, "")),
        )

    inventory = _hint(refs, INVENTORY_PREFIX)
    ttl = _hint(refs, TTL_PREFIX)
    conn.execute(
        "INSERT INTO tool_inventory_observations "
        "(tenant_id,server_name,inventory_hash,ttl_ms,cache_scope) "
        "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,server_name) DO UPDATE SET "
        "observed_at=now(),inventory_hash=EXCLUDED.inventory_hash,"
        "ttl_ms=EXCLUDED.ttl_ms,cache_scope=EXCLUDED.cache_scope",
        (
            tenant_id, server_name, inventory or "",
            int(ttl) if ttl and ttl.isdigit() else None,
            _hint(refs, SCOPE_PREFIX),
        ),
    )

    poisoned = tuple(
        (name, tuple(matches))
        for name, description in sorted(descriptions.items())
        if name in observed and (matches := poison_matches(description))
    )
    return tuple(changed), poisoned


def inventory_confidence(
    conn: Connection, tenant_id: str, server_name: str
) -> dict[str, Any]:
    """How stale our view of this server's tools is.

    The 2026-07-28 spec added ttlMs and cacheScope so clients cache list
    results and poll less. Fewer tools/list calls on the wire means a weaker
    drift signal, so this reports time since last observed ground truth rather
    than implying continuous coverage. Saying "unchanged" when the honest
    answer is "unknown" would be the same class of error as defaulting an
    unknown protocol version.
    """
    row = conn.execute(
        "SELECT observed_at,ttl_ms,cache_scope FROM tool_inventory_observations "
        "WHERE tenant_id=%s AND server_name=%s",
        (tenant_id, server_name),
    ).fetchone()
    if row is None:
        return {"state": "never_observed", "seconds_since_observed": None}
    observed_at = row[0].replace(tzinfo=UTC) if row[0].tzinfo is None else row[0]
    age = (datetime.now(UTC) - observed_at).total_seconds()
    ttl_seconds = (int(row[1]) / 1000) if row[1] else None
    return {
        "state": "stale" if ttl_seconds is not None and age > ttl_seconds else "fresh",
        "seconds_since_observed": round(age, 1),
        "last_observed_at": observed_at.isoformat(),
        "ttl_seconds": ttl_seconds,
        "cache_scope": row[2],
        "note": (
            "Client-side caching means the inventory may change without a "
            "tools/list call crossing the tap. This is the last time we saw "
            "ground truth, not a guarantee of continuous coverage."
        ),
    }
