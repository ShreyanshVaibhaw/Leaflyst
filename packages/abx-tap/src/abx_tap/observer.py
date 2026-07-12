"""JSON-RPC observer: parse copied lines into IngestEvent dicts.

Runs off the hot path (its own thread, fed by the pump's queue). Handles:
- both directions, with direction-aware request/response correlation by id
  (responses can arrive out of order; requests and ids can originate on
  either side - the client calls tools, the server calls sampling/roots),
- notifications (no id, no response),
- initialize handshake logging (protocolVersion, declared capabilities),
- tools/list inventory hashing for rug-pull/drift detection,
- resource_ref extraction from arguments (path/URI-shaped strings).

Spec-version awareness: built against 2025-11-25 semantics (initialize
handshake present). The 2026-07-28 revision drops the handshake; nothing here
requires it - events simply lack the protocol metadata when it never appears.

Event shapes follow packages/schemas/schema/ingest.schema.json. Dicts are
built by hand to keep the tap dependency-free; the schema contract is
enforced by tests that validate against the generated IngestEvent model.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from abx_tap.pump import CLIENT_TO_SERVER, ObservedLine

# Methods whose params may reference resources; used for ref extraction.
_PATHISH = re.compile(r"^(?:/|[A-Za-z]:[\\/]|file://|https?://|s3://|postgres(?:ql)?://)")


def format_ts(ts: datetime) -> str:
    ts = ts.astimezone(UTC)
    return ts.strftime("%Y-%m-%dT%H:%M:%S") + f".{ts.microsecond // 1000:03d}Z"


def _extract_resource_refs(value: Any, out: list[str], limit: int = 20) -> None:
    """Collect path/URI-shaped strings from params, best-effort."""
    if len(out) >= limit:
        return
    if isinstance(value, str):
        if _PATHISH.match(value) and value not in out:
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _extract_resource_refs(v, out, limit)
    elif isinstance(value, list):
        for v in value:
            _extract_resource_refs(v, out, limit)


def tools_hash(tools: list[dict[str, Any]]) -> str:
    """Stable hash of the tool inventory (name + description + schema)."""
    doc = sorted(
        (
            t.get("name", ""),
            t.get("description", ""),
            json.dumps(t.get("inputSchema", {}), sort_keys=True),
        )
        for t in tools
    )
    return hashlib.sha256(json.dumps(doc).encode()).hexdigest()


class Observer:
    """Stateful per-session message observer producing IngestEvent dicts."""

    def __init__(self, agent_id: str, server_name: str) -> None:
        self.agent_id = agent_id
        self.server_name = server_name
        self.session_id = f"tap-{uuid.uuid4()}"
        self.seq = 0
        # (direction, id) -> (method, params, monotonic start). Direction is
        # part of the key: both sides may use the same numeric ids.
        self.pending: dict[tuple[str, str], tuple[str, Any, float]] = {}
        self.protocol_version: str | None = None
        self.last_tools_hash: str | None = None

    def _base_event(self, event_type: str, name: str, target: str | None,
                    outcome: str, duration_ms: int | None,
                    resource_refs: list[str], payload: str | None) -> dict[str, Any]:
        self.seq += 1
        return {
            "event_id": str(uuid.uuid4()),
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "seq": self.seq - 1,
            "ts": format_ts(datetime.now(UTC)),
            "source": "mcp_tap",
            "event_type": event_type,
            "operation": {
                "name": name,
                "provider": self.server_name,
                "target": target,
                "outcome": outcome,
                "duration_ms": duration_ms,
            },
            "credential_ref": None,
            "resource_refs": resource_refs,
            "payload": payload,
        }

    def observe(self, line: ObservedLine) -> list[dict[str, Any]]:
        """Parse one line; return zero or more IngestEvent dicts.

        Never raises: observation failures must not affect the agent.
        """
        try:
            return self._observe(line)
        except Exception:
            return []

    def _observe(self, line: ObservedLine) -> list[dict[str, Any]]:
        msg = json.loads(line.raw.decode("utf-8", errors="replace"))
        if not isinstance(msg, dict):
            return []
        direction = line.direction

        if "method" in msg:
            method = str(msg["method"])
            params = msg.get("params")
            if "id" in msg:  # request: remember for correlation
                self.pending[(direction, str(msg["id"]))] = (
                    method, params, time.monotonic(),
                )
                if method == "initialize" and isinstance(params, dict):
                    self.protocol_version = params.get("protocolVersion")
                refs: list[str] = []
                _extract_resource_refs(params, refs)
                target = None
                if isinstance(params, dict):
                    target = params.get("name") or params.get("uri")
                return [self._base_event(
                    "mcp_request",
                    f"{method} {target}" if target else method,
                    target if isinstance(target, str) else None,
                    "unknown",  # outcome arrives with the response
                    None,
                    refs,
                    line.raw.decode("utf-8", errors="replace"),
                )]
            # notification: fire-and-forget
            refs = []
            _extract_resource_refs(params, refs)
            return [self._base_event(
                "mcp_request", method, None, "success", None, refs,
                line.raw.decode("utf-8", errors="replace"),
            )]

        if "id" in msg and ("result" in msg or "error" in msg):
            # Response travels opposite to its request.
            req_direction = (
                CLIENT_TO_SERVER if direction != CLIENT_TO_SERVER else "s2c"
            )
            pending = self.pending.pop((req_direction, str(msg["id"])), None)
            if pending is None:
                return []
            method, params, started = pending
            duration_ms = int((time.monotonic() - started) * 1000)
            outcome = "error" if "error" in msg else "success"
            target = None
            if isinstance(params, dict):
                target = params.get("name") or params.get("uri")
            payload = line.raw.decode("utf-8", errors="replace")

            if method == "tools/list" and "result" in msg:
                tools = msg["result"].get("tools", [])
                h = tools_hash(tools) if isinstance(tools, list) else None
                if h is not None:
                    drift = self.last_tools_hash is not None and h != self.last_tools_hash
                    self.last_tools_hash = h
                    refs = [f"abx:tool-inventory:{h}"]
                    if drift:
                        refs.append("abx:tool-drift:true")
                    payload = json.dumps(
                        {"tools_hash": h, "drifted": drift, "raw": payload}
                    )
                else:
                    refs = []
            else:
                refs = []
            _extract_resource_refs(msg.get("result"), refs)
            return [self._base_event(
                "mcp_response",
                f"{method} {target}" if target else method,
                target if isinstance(target, str) else None,
                outcome,
                duration_ms,
                refs,
                payload,
            )]

        return []
