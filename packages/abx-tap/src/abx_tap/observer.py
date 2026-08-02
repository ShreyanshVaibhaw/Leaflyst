"""JSON-RPC observer: parse copied lines into IngestEvent dicts.

Runs off the hot path (its own thread, fed by the pump's queue). Handles:
- both directions, with direction-aware request/response correlation by id
  (responses can arrive out of order; requests and ids can originate on
  either side - the client calls tools, the server calls sampling/roots),
- notifications (no id, no response),
- protocol/identity metadata from BOTH eras (see below),
- multi round-trip requests, correlated into one logical operation,
- tools/list inventory hashing for rug-pull/drift detection,
- W3C trace context, the join to SDK-captured LLM spans,
- resource_ref extraction from arguments (path/URI-shaped strings).

Spec-version awareness (blueprint2 14.1): both MCP eras are supported and
coexist. Legacy (<= 2025-11-25) declares protocol version once in the
`initialize` handshake. Modern (>= 2026-07-28) removed that handshake and
declares version, client identity, and capabilities in `_meta` on every
request. Literal protocol strings live only in mcp_spec.py.

When neither era yields a version the session is marked
`abx:mcp-protocol:unknown` explicitly. Silently defaulting would be the same
class of error as hiding a seq gap: absence of evidence must itself be evident.

Derived metadata rides in `resource_refs` under the `abx:` namespace rather
than in new event fields, so nothing here requires a schema change.

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

from abx_tap import mcp_spec
from abx_tap.pump import CLIENT_TO_SERVER, ObservedLine

# Methods whose params may reference resources; used for ref extraction.
_PATHISH = re.compile(r"^(?:/|[A-Za-z]:[\\/]|file://|https?://|s3://|postgres(?:ql)?://)")

# ponytail: a server that never answers would otherwise grow `pending`
# without bound. Oldest-first eviction; correlation is best-effort by design.
_MAX_PENDING = 10_000

# resource_refs is capped by the ingest contract; bound per-tool digests well
# under it and report the overflow rather than dropping it quietly.
_MAX_TOOL_REFS = 200

# Tap-authored observation line. Never crosses the wire in either direction;
# it only carries derived refs (auth fingerprints, stream incompleteness) from
# the HTTP tap into the observation queue, where the stdio pump would have had
# the raw bytes to derive them from.
ABX_OBSERVATION = "abx/observation"


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


def _tool_identity(tool: dict[str, Any]) -> tuple[str, str, str]:
    return (
        tool.get("name", ""),
        tool.get("description", ""),
        json.dumps(tool.get("inputSchema", {}), sort_keys=True),
    )


def tools_hash(tools: list[dict[str, Any]]) -> str:
    """Stable hash of the tool inventory (name + description + schema)."""
    return hashlib.sha256(json.dumps(sorted(map(_tool_identity, tools))).encode()).hexdigest()


def tool_digest(tool: dict[str, Any]) -> str:
    """Stable hash of ONE tool definition.

    The inventory hash proves something changed; a per-tool digest says which
    tool changed, which is what a rug-pull finding has to name. Digests ride in
    resource_refs, so they survive even when payload capture is off - the
    diff text needs the payload, but the detection does not.
    """
    return hashlib.sha256(json.dumps(_tool_identity(tool)).encode()).hexdigest()


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
        self.protocol_era: str = mcp_spec.ERA_UNKNOWN
        self.client_info: str | None = None
        # Self-reported by the server and NOT verified by the protocol; the
        # spec says explicitly not to make security decisions on it. Recorded
        # as a claim, never as identity.
        self.server_info_claim: str | None = None
        self.supported_versions: list[str] = []
        self.last_tools_hash: str | None = None
        # Correlation key -> multi round-trip id, so an interim
        # `input_required` result and its retry read as one operation.
        self._mrtr: dict[str, str] = {}
        self._announced: str | None = None

    # -- derived markers ----------------------------------------------------

    def _protocol_markers(self) -> list[str]:
        """Protocol refs, emitted only when the determination changes."""
        version = self.protocol_version or mcp_spec.PROTOCOL_UNKNOWN
        current = f"{version}/{self.protocol_era}"
        if current == self._announced:
            return []
        self._announced = current
        return [f"abx:mcp-protocol:{version}", f"abx:mcp-era:{self.protocol_era}"]

    def _note_protocol(self, method: str, params: Any) -> None:
        version, era = mcp_spec.protocol_version_of_request(method, params)
        if version is not None:
            self.protocol_version = version
            self.protocol_era = era
        info = mcp_spec.describe_party(mcp_spec.meta_of(params).get(mcp_spec.META_CLIENT_INFO))
        if info is not None:
            self.client_info = info

    def _mrtr_key(self, method: str, body: Any) -> str:
        """Correlation key for a multi round-trip exchange.

        Servers needing to correlate across retries encode their own
        identifier in `requestState`; when absent, the method alone is the
        key, which is correct while one exchange per method is outstanding.
        """
        state = body.get("requestState") if isinstance(body, dict) else None
        if state is None:
            return method
        return f"{method}\x00{json.dumps(state, sort_keys=True, default=str)}"

    def _remember(self, key: tuple[str, str], value: tuple[str, Any, float]) -> None:
        self.pending[key] = value
        while len(self.pending) > _MAX_PENDING:
            self.pending.pop(next(iter(self.pending)))

    # -- event construction -------------------------------------------------

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
            return self._observe_outbound(msg, direction, line)
        if "id" in msg and ("result" in msg or "error" in msg):
            return self._observe_reply(msg, direction, line)
        return []

    def _observe_outbound(
        self, msg: dict[str, Any], direction: str, line: ObservedLine
    ) -> list[dict[str, Any]]:
        """A request or a notification."""
        method = str(msg["method"])
        params = msg.get("params")
        if method == ABX_OBSERVATION:
            return self._observation(params, line)
        meta = mcp_spec.meta_of(params)
        self._note_protocol(method, params)

        refs: list[str] = self._protocol_markers()
        trace_id = mcp_spec.trace_id_of(meta)
        if trace_id:
            refs.append(f"abx:trace:{trace_id}")
        subscription = meta.get(mcp_spec.META_SUBSCRIPTION_ID)
        if isinstance(subscription, str) and subscription:
            refs.append(f"abx:mcp-subscription:{subscription}")

        raw = line.raw.decode("utf-8", errors="replace")

        if "id" not in msg:  # notification: fire-and-forget
            _extract_resource_refs(params, refs)
            return [self._base_event(
                "mcp_request", method, None, "success", None, refs, raw,
            )]

        self._remember((direction, str(msg["id"])), (method, params, time.monotonic()))

        # A retry carrying `inputResponses` continues an earlier exchange.
        if isinstance(params, dict) and "inputResponses" in params:
            mrtr_id = self._mrtr.get(self._mrtr_key(method, params))
            if mrtr_id:
                refs.append(f"abx:mrtr:{mrtr_id}")

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
            raw,
        )]

    def _observation(self, params: Any, line: ObservedLine) -> list[dict[str, Any]]:
        """Record a tap-authored observation (HTTP transport only).

        Carries no payload: these lines describe the transport, not agent I/O,
        and the raw request bytes were already recorded on their own event.
        """
        refs = mcp_spec.string_list(params.get("refs") if isinstance(params, dict) else None)
        if not refs:
            return []
        del line
        return [self._base_event(
            "mcp_request", "transport observation", None, "success", None,
            [*self._protocol_markers(), *refs[:64]], None,
        )]

    def _observe_reply(
        self, msg: dict[str, Any], direction: str, line: ObservedLine
    ) -> list[dict[str, Any]]:
        """A result or an error, travelling opposite to its request."""
        req_direction = CLIENT_TO_SERVER if direction != CLIENT_TO_SERVER else "s2c"
        pending = self.pending.pop((req_direction, str(msg["id"])), None)
        if pending is None:
            return []
        method, params, started = pending
        duration_ms = int((time.monotonic() - started) * 1000)
        result = msg.get("result")
        outcome = "error" if "error" in msg else "success"
        target = None
        if isinstance(params, dict):
            target = params.get("name") or params.get("uri")
        payload = line.raw.decode("utf-8", errors="replace")
        refs: list[str] = []

        meta = mcp_spec.meta_of(result)
        # Modern servers identify in result `_meta`; legacy put serverInfo at
        # the top level of the initialize result. Both are self-reported.
        claim = mcp_spec.describe_party(meta.get(mcp_spec.META_SERVER_INFO))
        if claim is None and method == mcp_spec.METHOD_INITIALIZE and isinstance(result, dict):
            claim = mcp_spec.describe_party(result.get("serverInfo"))
        if claim is not None and claim != self.server_info_claim:
            self.server_info_claim = claim
            refs.append(f"abx:mcp-server-claimed:{claim}")
        trace_id = mcp_spec.trace_id_of(meta)
        if trace_id:
            refs.append(f"abx:trace:{trace_id}")
        subscription = meta.get(mcp_spec.META_SUBSCRIPTION_ID)
        if isinstance(subscription, str) and subscription:
            refs.append(f"abx:mcp-subscription:{subscription}")

        if "error" in msg:
            refs.extend(self._error_refs(msg["error"]))
        elif method == mcp_spec.METHOD_DISCOVER:
            refs.extend(self._discover_refs(result))
        elif method == mcp_spec.METHOD_TOOLS_LIST:
            inventory_refs, payload = self._tools_list(result, payload)
            refs.extend(inventory_refs)

        # Interim result: the operation is not finished, and its retry must
        # read as the same operation rather than an unrelated second call.
        if mcp_spec.result_type(result) == mcp_spec.RESULT_INPUT_REQUIRED:
            key = self._mrtr_key(method, result)
            mrtr_id = self._mrtr.setdefault(key, uuid.uuid4().hex[:12])
            refs.append(f"abx:mrtr:{mrtr_id}")
            outcome = "unknown"
        else:
            closing = self._mrtr.pop(self._mrtr_key(method, result), None)
            if closing:
                refs.append(f"abx:mrtr:{closing}")

        _extract_resource_refs(result, refs)
        return [self._base_event(
            "mcp_response",
            f"{method} {target}" if target else method,
            target if isinstance(target, str) else None,
            outcome,
            duration_ms,
            refs,
            payload,
        )]

    def _error_refs(self, error: Any) -> list[str]:
        """Protocol-level errors worth surfacing as their own signal."""
        if not isinstance(error, dict):
            return []
        if error.get("code") != mcp_spec.ERR_UNSUPPORTED_PROTOCOL_VERSION:
            return []
        raw_data = error.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        requested = data.get("requested")
        supported = mcp_spec.string_list(data.get("supported"))
        if supported:
            self.supported_versions = supported
        label = requested if isinstance(requested, str) and requested else "unspecified"
        return [f"abx:mcp-version-rejected:{label}"]

    def _discover_refs(self, result: Any) -> list[str]:
        """A DiscoverResult identifies a modern server."""
        versions = mcp_spec.supported_versions_of(result)
        if not versions:
            return []
        self.supported_versions = versions
        refs = [f"abx:mcp-supported:{','.join(versions)}"]
        if self.protocol_era == mcp_spec.ERA_UNKNOWN:
            self.protocol_era = mcp_spec.ERA_MODERN
            self._announced = None
            refs.extend(self._protocol_markers())
        return refs

    def _tools_list(self, result: Any, payload: str) -> tuple[list[str], str]:
        """Inventory hash, per-tool digests, and cache hints.

        Feeds inventory drift (rule 5), rug pull (rule 6), and tool poisoning
        (rule 7). The per-tool digests are what let a finding name the tool that
        changed rather than only that the set did.
        """
        tools = result.get("tools", []) if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return [], payload
        digest = tools_hash(tools)
        drift = self.last_tools_hash is not None and digest != self.last_tools_hash
        self.last_tools_hash = digest
        refs = [f"abx:tool-inventory:{digest}"]
        if drift:
            refs.append("abx:tool-drift:true")
        for tool in tools[:_MAX_TOOL_REFS]:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                refs.append(f"abx:tool-def:{tool['name']}:{tool_digest(tool)[:16]}")
        if len(tools) > _MAX_TOOL_REFS:
            # Never silently truncate coverage: say how many went unrecorded.
            refs.append(f"abx:tool-refs-truncated:{len(tools) - _MAX_TOOL_REFS}")
        ttl_ms, cache_scope = mcp_spec.cache_hints(result)
        if ttl_ms is not None:
            refs.append(f"abx:tool-cache-ttl-ms:{ttl_ms}")
        if cache_scope is not None:
            refs.append(f"abx:tool-cache-scope:{cache_scope}")
        return refs, json.dumps({
            "tools_hash": digest,
            "drifted": drift,
            "ttl_ms": ttl_ms,
            "cache_scope": cache_scope,
            "raw": payload,
        })
