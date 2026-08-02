"""Build a per-agent behavioural baseline from recorded history.

One ClickHouse round trip per evaluated event, aggregated server-side rather
than pulled into Python: an agent with months of history must not turn alert
evaluation into a full scan.

The window deliberately EXCLUDES the session being scored. Otherwise the event
under evaluation contributes to the baseline it is measured against, which
makes a novel operation look slightly less novel the more of it there is - the
opposite of what should happen.
"""

from __future__ import annotations

from typing import Any

from abx_rules.baseline import AgentBaseline, Observation

from abx_api.store import ch_client

BASELINE_WINDOW_DAYS = 30

# Resource refs are '<provider>:<kind>:<identifier>'; the first two segments
# are the class. Anything else is grouped under its first segment so a
# malformed ref cannot masquerade as a new resource class every time.
def resource_kind(ref: str) -> str:
    parts = ref.split(":")
    if len(parts) >= 3:
        return f"{parts[0]}:{parts[1]}"
    return parts[0] if parts else "unknown"


def build_baseline(tenant_id: str, agent_id: str, session_id: str) -> AgentBaseline:
    rows = ch_client().query(
        "SELECT "
        "  dateDiff('day', min(ts), now()) AS days, "
        "  uniqExact(session_id) AS sessions, "
        "  groupUniqArray(op_name) AS operations, "
        "  groupUniqArray(credential_ref) AS credentials, "
        "  groupArrayDistinct(toHour(ts)) AS hours "
        "FROM events "
        "WHERE tenant_id=%(tenant)s AND agent_id=%(agent)s "
        "  AND session_id != %(session)s "
        "  AND ts >= now() - INTERVAL %(window)s DAY",
        parameters={
            "tenant": tenant_id, "agent": agent_id,
            "session": session_id, "window": BASELINE_WINDOW_DAYS,
        },
    ).result_rows
    if not rows or not rows[0]:
        return AgentBaseline()
    days, sessions, operations, credentials, _hours = rows[0]

    hourly_rows = ch_client().query(
        "SELECT toHour(ts) AS hour, count() AS n FROM events "
        "WHERE tenant_id=%(tenant)s AND agent_id=%(agent)s "
        "  AND session_id != %(session)s "
        "  AND ts >= now() - INTERVAL %(window)s DAY "
        "GROUP BY hour",
        parameters={
            "tenant": tenant_id, "agent": agent_id,
            "session": session_id, "window": BASELINE_WINDOW_DAYS,
        },
    ).result_rows

    kinds = ch_client().query(
        "SELECT DISTINCT arrayJoin(resource_refs) AS ref FROM events "
        "WHERE tenant_id=%(tenant)s AND agent_id=%(agent)s "
        "  AND session_id != %(session)s "
        "  AND ts >= now() - INTERVAL %(window)s DAY "
        "LIMIT 10000",
        parameters={
            "tenant": tenant_id, "agent": agent_id,
            "session": session_id, "window": BASELINE_WINDOW_DAYS,
        },
    ).result_rows

    return AgentBaseline(
        days_observed=float(days or 0),
        sessions=int(sessions or 0),
        operations=frozenset(str(value) for value in (operations or []) if value),
        resource_kinds=frozenset(resource_kind(str(row[0])) for row in kinds if row[0]),
        credentials=frozenset(str(value) for value in (credentials or []) if value),
        hourly={int(row[0]): int(row[1]) for row in hourly_rows},
    )


def observation_of(event: dict[str, Any]) -> Observation:
    raw_refs = event.get("resource_refs")
    refs = list(raw_refs) if isinstance(raw_refs, (list, tuple)) else []
    hour = getattr(event.get("ts"), "hour", None)
    return Observation(
        operation=str(event.get("op_name") or ""),
        resource_kinds=frozenset(resource_kind(str(ref)) for ref in refs),
        credential_ref=str(event.get("credential_ref") or "") or None,
        hour=int(hour) if hour is not None else None,
    )
