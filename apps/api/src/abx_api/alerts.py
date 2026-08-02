"""Explainable anomaly evaluation and best-effort Slack/email dispatch."""

from __future__ import annotations

import json
import logging
import statistics
import urllib.request
from datetime import UTC, datetime
from typing import Any

from abx_rules import EventFacts, evaluate
from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

from abx_api.baselines import build_baseline, observation_of
from abx_api.identifiers import ResourceId
from abx_api.rbac import require_configure, require_read, require_triage
from abx_api.settings import settings
from abx_api.store import ch_client, get_payload, pg_pool
from abx_api.tool_integrity import TOOL_DEF_PREFIX, record_and_diff

router = APIRouter(prefix="/v1/alerts", dependencies=[Depends(require_read)])
logger = logging.getLogger(__name__)


class AlertView(BaseModel):
    id: str
    rule_id: str
    severity: str
    title: str
    agent_id: str
    credential_ref: str | None
    event_id: str
    session_id: str
    evidence: dict[str, Any]
    status: str
    hit_count: int
    first_seen: str
    last_seen: str
    dispatch_status: dict[str, Any]


class ChannelConfig(BaseModel):
    kind: str
    target: str = ""
    enabled: bool = True
    secret_configured: bool = False


class ChannelUpdate(BaseModel):
    kind: str
    target: str = Field(default="", max_length=320)
    enabled: bool = True


def _ch_rows(sql: str, params: dict[str, object]) -> list[dict[str, Any]]:
    result = ch_client().query(sql, parameters=params)
    return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]


@router.get("", response_model=list[AlertView])
def alert_list(tenant_id: str, status: str = "open") -> list[AlertView]:
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT id, rule_id, severity, title, agent_id, credential_ref, event_id, "
            "session_id, evidence, status, hit_count, first_seen, last_seen, dispatch_status "
            "FROM alerts WHERE tenant_id = %s AND status = %s ORDER BY last_seen DESC",
            (tenant_id, status),
        ).fetchall()
    return [AlertView(
        id=str(row[0]), rule_id=row[1], severity=row[2], title=row[3], agent_id=row[4],
        credential_ref=row[5], event_id=str(row[6]), session_id=row[7], evidence=row[8],
        status=row[9], hit_count=row[10], first_seen=row[11].isoformat(),
        last_seen=row[12].isoformat(), dispatch_status=row[13],
    ) for row in rows]


@router.post(
    "/{alert_id}/acknowledge",
    response_model=dict[str, str],
    dependencies=[Depends(require_triage)],
)
def acknowledge(tenant_id: str, alert_id: ResourceId) -> dict[str, str]:
    with pg_pool().connection() as conn:
        row = conn.execute(
            "UPDATE alerts SET status = 'acknowledged' WHERE tenant_id = %s AND id = %s "
            "RETURNING id", (tenant_id, alert_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return {"status": "acknowledged"}


@router.get("/channels", response_model=list[ChannelConfig])
def channels(tenant_id: str) -> list[ChannelConfig]:
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT kind, target, enabled FROM alert_channels WHERE tenant_id = %s "
            "ORDER BY kind", (tenant_id,),
        ).fetchall()
    configured = {
        "slack": bool(settings.slack_webhook_url),
        "email": bool(settings.resend_api_key),
    }
    return [ChannelConfig(
        kind=row[0], target=row[1], enabled=row[2],
        secret_configured=configured.get(row[0], False),
    ) for row in rows]


# Alert delivery is configuration: a read-only principal that could rewrite
# it could route this tenant's security alerts to an address it controls,
# or disable delivery entirely and blind the tenant's detection.
@router.put(
    "/channels",
    response_model=ChannelConfig,
    dependencies=[Depends(require_configure)],
)
def update_channel(tenant_id: str, update: ChannelUpdate) -> ChannelConfig:
    if update.kind not in {"slack", "email"}:
        raise HTTPException(status_code=422, detail="unsupported alert channel")
    if update.kind == "email" and ("@" not in update.target or "\n" in update.target):
        raise HTTPException(status_code=422, detail="valid email target required")
    target = update.target.strip() if update.kind == "email" else ""
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO alert_channels (tenant_id, kind, target, enabled) "
            "VALUES (%s, %s, %s, %s) ON CONFLICT (tenant_id, kind, target) "
            "DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()",
            (tenant_id, update.kind, target, update.enabled),
        )
    configured = bool(
        settings.slack_webhook_url if update.kind == "slack" else settings.resend_api_key
    )
    return ChannelConfig(
        kind=update.kind, target=target, enabled=update.enabled,
        secret_configured=configured,
    )


@router.post(
    "/evaluate",
    response_model=dict[str, int],
    dependencies=[Depends(require_configure)],
)
def evaluate_all(tenant_id: str) -> dict[str, int]:
    rows = _ch_rows(
        "SELECT event_id FROM events WHERE tenant_id = %(tenant)s ORDER BY chain_seq DESC "
        "LIMIT 1000", {"tenant": tenant_id},
    )
    return {"alerts": evaluate_event_ids(tenant_id, [str(row["event_id"]) for row in rows])}


def evaluate_event_ids(tenant_id: str, event_ids: list[str]) -> int:
    created = 0
    for event_id in event_ids:
        rows = _ch_rows(
            "SELECT * FROM events WHERE tenant_id = %(tenant)s AND event_id = %(event)s "
            "ORDER BY chain_seq DESC LIMIT 1",
            {"tenant": tenant_id, "event": event_id},
        )
        if not rows:
            continue
        event = rows[0]
        facts = _facts(tenant_id, event)
        for candidate in evaluate(facts):
            if _upsert_and_maybe_dispatch(tenant_id, event, candidate):
                created += 1
    return created


def _facts(tenant_id: str, event: dict[str, Any]) -> EventFacts:
    credential = str(event["credential_ref"] or "")
    refs = tuple(str(ref) for ref in event["resource_refs"])
    with pg_pool().connection() as conn:
        scan_row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM scan_runs WHERE tenant_id = %s "
            "AND status = 'succeeded')", (tenant_id,),
        ).fetchone()
        assert scan_row is not None
        scan = scan_row[0]
        flagged = False
        allowed: set[str] = set()
        if credential:
            row = conn.execute(
                "SELECT id, owner_principal FROM credentials WHERE tenant_id = %s "
                "AND fingerprint = %s", (tenant_id, credential),
            ).fetchone()
            if row:
                flagged_row = conn.execute(
                    "SELECT EXISTS(SELECT 1 FROM findings WHERE tenant_id = %s "
                    "AND credential_id = %s AND status = 'open')", (tenant_id, row[0]),
                ).fetchone()
                assert flagged_row is not None
                flagged = flagged_row[0]
                allowed = {value[0] for value in conn.execute(
                    "SELECT DISTINCT r.identifier FROM permissions p "
                    "JOIN permission_reaches_resource pr ON pr.permission_id = p.id "
                    "JOIN resources r ON r.id = pr.resource_id "
                    "WHERE p.tenant_id = %s AND (p.credential_id = %s OR p.principal_id = %s)",
                    (tenant_id, row[0], row[1]),
                ).fetchall()}
        agent = conn.execute(
            "SELECT environment, first_seen FROM agents WHERE tenant_id = %s AND name = %s",
            (tenant_id, event["agent_id"]),
        ).fetchone()
        prod_refs = {row[0] for row in conn.execute(
            "SELECT identifier FROM resources WHERE tenant_id = %s "
            "AND environment = 'prod' AND identifier = ANY(%s)",
            (tenant_id, list(refs)),
        ).fetchall()} if refs else set()
    sessions = _ch_rows(
        "SELECT session_id, count() AS n FROM events WHERE tenant_id = %(tenant)s "
        "AND agent_id = %(agent)s AND ts >= now() - INTERVAL 7 DAY GROUP BY session_id",
        {"tenant": tenant_id, "agent": event["agent_id"]},
    )
    current = next((int(row["n"]) for row in sessions
                    if row["session_id"] == event["session_id"]), 0)
    prior = [int(row["n"]) for row in sessions if row["session_id"] != event["session_id"]]
    recorded_start = _ch_rows(
        "SELECT min(ts) AS first_seen FROM events WHERE tenant_id=%(tenant)s "
        "AND agent_id=%(agent)s",
        {"tenant": tenant_id, "agent": event["agent_id"]},
    )[0]["first_seen"]
    candidates = [value for value in (agent[1] if agent else None, recorded_start) if value]
    aware_candidates = [
        value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        for value in candidates
    ]
    first_seen = min(aware_candidates, default=datetime.now(UTC))
    history_days = (datetime.now(UTC) - first_seen).total_seconds() / 86400
    inventory = next(
        (ref.removeprefix("abx:tool-inventory:") for ref in refs
         if ref.startswith("abx:tool-inventory:")),
        None,
    )
    inventory_drift = False
    if inventory:
        previous = _ch_rows(
            "SELECT resource_refs FROM events WHERE tenant_id=%(tenant)s "
            "AND agent_id=%(agent)s AND session_id != %(session)s "
            "AND arrayExists(x -> startsWith(x, 'abx:tool-inventory:'), resource_refs) "
            "ORDER BY ts DESC LIMIT 1",
            {"tenant": tenant_id, "agent": event["agent_id"],
             "session": event["session_id"]},
        )
        if previous:
            old = next((str(ref).removeprefix("abx:tool-inventory:")
                        for ref in previous[0]["resource_refs"]
                        if str(ref).startswith("abx:tool-inventory:")), None)
            inventory_drift = old is not None and old != inventory
    changed_tools: tuple[tuple[str, float, int], ...] = ()
    poisoned_tools: tuple[tuple[str, tuple[str, ...]], ...] = ()
    if any(ref.startswith(TOOL_DEF_PREFIX) for ref in refs):
        with pg_pool().connection() as conn:
            changed_tools, poisoned_tools = record_and_diff(
                conn,
                tenant_id,
                str(event.get("op_provider") or "unknown"),
                event["session_id"],
                list(refs),
                _payload_body(event),
            )
    # Rule 8 needs the agent's own history. Degrades to no baseline rather
    # than failing the whole evaluation: an unavailable baseline must not stop
    # the deterministic rules from firing.
    baseline = None
    observation = None
    try:
        baseline = build_baseline(tenant_id, event["agent_id"], event["session_id"])
        observation = observation_of(event)
    except Exception:  # noqa: BLE001
        logger.exception("behavioural baseline unavailable for tenant %s", tenant_id)

    return EventFacts(
        event_id=str(event["event_id"]), session_id=event["session_id"],
        agent_id=event["agent_id"], operation=event["op_name"],
        credential_ref=credential or None, resource_refs=refs,
        scanner_baseline=bool(scan), credential_flagged=bool(flagged),
        outside_scanned_scope=bool(allowed and any(ref not in allowed for ref in refs)),
        history_days=history_days, session_event_count=current,
        trailing_session_median=statistics.median(prior) if prior else None,
        environment_crossover=bool(agent and agent[0] != "prod" and prod_refs),
        tool_inventory_drift=inventory_drift,
        changed_tools=changed_tools,
        poisoned_tools=poisoned_tools,
        baseline=baseline,
        observation=observation,
    )


def _payload_body(event: dict[str, Any]) -> str | None:
    """The captured tools/list body, or None when capture is off.

    A missing payload means the description text is unknown, which the caller
    must treat as unknown rather than clean: detection of WHICH tool changed
    still works from resource_refs, but poisoning analysis cannot run.
    """
    ref = str(event.get("payload_ref") or "")
    if not ref:
        return None
    try:
        body = get_payload(ref)
    except Exception:  # noqa: BLE001 - analysis degrades, alerting continues
        return None
    return body.decode("utf-8", errors="replace") if body else None


def _upsert_and_maybe_dispatch(tenant_id: str, event: dict[str, Any], candidate: Any) -> bool:
    credential = str(event["credential_ref"] or "")
    dedupe = f"{candidate.rule_id}:{event['agent_id']}:{credential or '-'}"
    with pg_pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO alerts (tenant_id, rule_id, dedupe_key, severity, title, agent_id, "
            "credential_ref, event_id, session_id, evidence) VALUES "
            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (tenant_id, dedupe_key) "
            "DO UPDATE SET event_id=EXCLUDED.event_id, session_id=EXCLUDED.session_id, "
            "evidence=EXCLUDED.evidence, hit_count=alerts.hit_count+1, last_seen=now() "
            "RETURNING id, last_dispatched_at",
            (tenant_id, candidate.rule_id, dedupe, candidate.severity, candidate.title,
             event["agent_id"], credential or None, str(event["event_id"]),
             event["session_id"], Jsonb(candidate.evidence)),
        ).fetchone()
        assert row is not None
        last = row[1]
        due = last is None or (
            datetime.now(UTC) - last.astimezone(UTC)
        ).total_seconds() >= settings.alert_cooldown_minutes * 60
        if due:
            status = dispatch_alert(tenant_id, str(row[0]), candidate.title, event["session_id"])
            conn.execute(
                "UPDATE alerts SET last_dispatched_at=now(), dispatch_status=%s "
                "WHERE tenant_id=%s AND id=%s", (Jsonb(status), tenant_id, row[0]),
            )
    return last is None


def dispatch_alert(tenant_id: str, alert_id: str, title: str, session_id: str) -> dict[str, str]:
    link = f"{settings.web_url.rstrip('/')}/sessions/{session_id}"
    message = f"Leaflyst: {title}\n{link}"
    status: dict[str, str] = {}
    with pg_pool().connection() as conn:
        channels = conn.execute(
            "SELECT kind, target FROM alert_channels WHERE tenant_id=%s AND enabled=true",
            (tenant_id,),
        ).fetchall()
    for kind, target in channels:
        try:
            if kind == "slack" and settings.slack_webhook_url:
                _post_json(settings.slack_webhook_url, {"text": message})
                status["slack"] = "sent"
            elif kind == "email" and settings.resend_api_key:
                _post_json(
                    "https://api.resend.com/emails",
                    {"from": settings.alert_email_from, "to": [target],
                     "subject": title, "text": message},
                    {"Authorization": f"Bearer {settings.resend_api_key}",
                     "Idempotency-Key": f"alert-{alert_id}"},
                )
                status["email"] = "sent"
            else:
                status[kind] = "not_configured"
        except Exception:
            logger.exception("alert dispatch failed for %s", kind)
            status[kind] = "failed"
    return status


def _post_json(url: str, body: dict[str, object], headers: dict[str, str] | None = None) -> None:
    request = urllib.request.Request(  # noqa: S310 - configured HTTPS provider endpoint
        url, method="POST", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        if response.status >= 300:
            raise RuntimeError(f"alert provider returned {response.status}")
