"""Chain control-plane actions into the tenant's own event chain.

The recording plane is append-only and tamper-evident. The control plane that
governs it was not, which left an obvious gap: an attacker who could not edit
the record could still quietly widen a retention policy, mint a token, or
change a role, and nothing tamper-evident would show it.

So configuration changes go into the same hash chain as agent activity, and
verify the same way. An auditor asking "did anyone change the rules during this
period" gets an answer with the same standing as the events themselves.

Recording must never block the action: an admin change that succeeded but could
not be chained is reported as the degradation it is, not rolled back.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from abx_schemas import IngestEvent

logger = logging.getLogger(__name__)


def record_admin_action(
    tenant_id: str,
    action: str,
    target: str,
    detail: dict[str, Any] | None = None,
    *,
    outcome: str = "success",
    actor_role: str | None = None,
) -> bool:
    """Chain one control-plane action. Returns whether it was recorded."""
    from abx_api.ingest import ingest_events

    refs = [f"abx:admin-action:{action}"]
    if actor_role:
        refs.append(f"abx:actor-role:{actor_role}")
    event = IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()),
        "agent_id": "abx-admin",
        "session_id": f"admin:{uuid.uuid4()}",
        "seq": 0,
        "ts": datetime.now(UTC),
        "source": "admin_api",
        "event_type": "agent_step",
        "operation": {
            "name": action, "provider": "leaflyst", "target": target,
            "outcome": outcome, "duration_ms": 0,
        },
        "resource_refs": refs,
        "payload": json.dumps(detail or {}, default=str),
    })
    try:
        ingest_events(tenant_id, [event])
    except Exception:  # noqa: BLE001 - the action already happened
        logger.exception("admin action %s was not chained for tenant %s", action, tenant_id)
        return False
    return True
