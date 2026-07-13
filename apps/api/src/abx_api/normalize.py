"""OTLP trace normalization into canonical AgentBlackBox ingest events.

This is the ONLY ingest module allowed to contain raw ``gen_ai.*`` strings.
It accepts current and legacy OTel GenAI attributes plus OpenLLMetry and
OpenInference shapes. Captured content remains untrusted text and flows through
the normal server-side redaction pipeline before storage.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.trace.v1.trace_pb2 import Span

from abx_api.auth import tenant_from_token
from abx_api.ingest import ingest_events
from abx_api.redaction import redact
from abx_api.store import pg_pool

router = APIRouter()
logger = logging.getLogger(__name__)

# Current OTel GenAI conventions, pinned to semantic-conventions v1.41.0.
GEN_AI_OPERATION = "gen_ai.operation.name"
GEN_AI_PROVIDER = "gen_ai.provider.name"
GEN_AI_SYSTEM_LEGACY = "gen_ai.system"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_RESPONSE_MODEL = "gen_ai.response.model"
GEN_AI_AGENT_ID = "gen_ai.agent.id"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_CONVERSATION_ID = "gen_ai.conversation.id"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_ARGS = "gen_ai.tool.call.arguments"
GEN_AI_TOOL_RESULT = "gen_ai.tool.call.result"
GEN_AI_INPUT_MESSAGES = "gen_ai.input.messages"
GEN_AI_OUTPUT_MESSAGES = "gen_ai.output.messages"
GEN_AI_SYSTEM_INSTRUCTIONS = "gen_ai.system_instructions"
GEN_AI_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
GEN_AI_PROMPT_TOKENS_LEGACY = "gen_ai.usage.prompt_tokens"
GEN_AI_COMPLETION_TOKENS_LEGACY = "gen_ai.usage.completion_tokens"
GEN_AI_PROMPT_LEGACY = "gen_ai.prompt"
GEN_AI_COMPLETION_LEGACY = "gen_ai.completion"

_CONTENT_KEYS = (
    GEN_AI_INPUT_MESSAGES,
    GEN_AI_OUTPUT_MESSAGES,
    GEN_AI_SYSTEM_INSTRUCTIONS,
    GEN_AI_TOOL_ARGS,
    GEN_AI_TOOL_RESULT,
    GEN_AI_PROMPT_LEGACY,
    GEN_AI_COMPLETION_LEGACY,
    "input.value",
    "output.value",
    "llm.prompts",
    "llm.completions",
)
_FINGERPRINT = re.compile(
    r"^(?:(?:aws:)?(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|"
    r"pat:[0-9]+|deploykey:[^\s]{1,220}|appinstall:[0-9]+)$"
)


@dataclass(frozen=True)
class NormalizedSpan:
    span: Span
    attributes: dict[str, Any]
    resource: dict[str, Any]
    scope_name: str


@router.post("/v1/otlp/traces")
@router.post("/v1/traces", include_in_schema=False)
async def otlp_traces(
    request: Request,
    tenant_id: Annotated[str, Depends(tenant_from_token)],
) -> Response:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip()
    if content_type != "application/x-protobuf":
        raise HTTPException(status_code=415, detail="OTLP protobuf is required")
    try:
        export_request = ExportTraceServiceRequest.FromString(await request.body())
    except DecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid OTLP trace protobuf") from exc

    events = normalize_export(export_request)
    if events:
        events = allocate_session_sequences(tenant_id, events)
        ingest_events(tenant_id, events)
        try:
            link_observed_credentials(tenant_id, events)
        except Exception:
            # Graph enrichment must never turn accepted telemetry into exporter
            # retries and duplicate event writes.
            logger.exception("credential graph enrichment failed for tenant %s", tenant_id)

    response = ExportTraceServiceResponse().SerializeToString()
    return Response(content=response, media_type="application/x-protobuf")


def normalize_export(request: ExportTraceServiceRequest) -> list[IngestEvent]:
    normalized: list[NormalizedSpan] = []
    for resource_spans in request.resource_spans:
        resource = _attributes(resource_spans.resource.attributes)
        for scope_spans in resource_spans.scope_spans:
            for span in scope_spans.spans:
                normalized.append(
                    NormalizedSpan(
                        span=span,
                        attributes=_attributes(span.attributes),
                        resource=resource,
                        scope_name=scope_spans.scope.name,
                    )
                )
    normalized.sort(key=lambda item: (item.span.start_time_unix_nano, item.span.span_id))
    events = [_to_ingest_event(item) for item in normalized]
    counters: dict[str, int] = {}
    sequenced: list[IngestEvent] = []
    for event in events:
        seq = counters.get(event.session_id, 0)
        counters[event.session_id] = seq + 1
        sequenced.append(event.model_copy(update={"seq": seq}))
    return sequenced


def _to_ingest_event(item: NormalizedSpan) -> IngestEvent:
    span, attrs = item.span, item.attributes
    operation = _operation(attrs, span.name)
    provider = _clean(
        attrs.get(GEN_AI_PROVIDER)
        or attrs.get(GEN_AI_SYSTEM_LEGACY)
        or attrs.get("llm.provider")
        or attrs.get("openinference.provider")
    )
    target = _clean(
        attrs.get(GEN_AI_TOOL_NAME)
        or attrs.get(GEN_AI_REQUEST_MODEL)
        or attrs.get(GEN_AI_RESPONSE_MODEL)
        or attrs.get("llm.model_name")
        or attrs.get("llm.request.model")
        or attrs.get("tool.name")
    )
    start_ns = int(span.start_time_unix_nano)
    end_ns = int(span.end_time_unix_nano)
    duration_ms = max(0, (end_ns - start_ns) // 1_000_000) if end_ns >= start_ns else 0
    trace_id = bytes(span.trace_id).hex() or str(uuid.uuid4())
    agent_id = _clean(
        attrs.get(GEN_AI_AGENT_ID)
        or attrs.get(GEN_AI_AGENT_NAME)
        or attrs.get("entity.name")
        or item.resource.get("service.name")
        or item.scope_name
        or "otel-agent"
    )
    credential_ref = _credential_ref(attrs)
    payload_values = {key: attrs[key] for key in _CONTENT_KEYS if key in attrs}
    payload = (
        json.dumps(payload_values, default=str, ensure_ascii=False)
        if payload_values else None
    )
    timestamp = (
        datetime.fromtimestamp(start_ns / 1_000_000_000, UTC)
        if start_ns else datetime.now(UTC)
    )
    return IngestEvent.model_validate(
        {
            "event_id": str(uuid.uuid4()),
            "agent_id": agent_id[:256],
            "session_id": _clean(attrs.get(GEN_AI_CONVERSATION_ID) or trace_id)[:256],
            "seq": 0,
            "ts": timestamp,
            "source": (
                "sdk_langgraph"
                if item.resource.get("abx.source") == "sdk_langgraph"
                else "otel_ingest"
            ),
            "event_type": _event_type(operation, attrs),
            "operation": {
                "name": _clean(span.name)[:512] or operation,
                "provider": provider[:256] if provider else None,
                "target": target[:512] if target else None,
                "outcome": "error" if span.status.code == 2 else "success",
                "duration_ms": duration_ms,
            },
            "credential_ref": credential_ref,
            "resource_refs": _resource_refs(attrs),
            "payload": payload,
        }
    )


def allocate_session_sequences(
    tenant_id: str, events: list[IngestEvent]
) -> list[IngestEvent]:
    """Allocate contiguous sequence numbers across concurrent OTLP batches."""
    grouped: dict[str, list[int]] = {}
    for index, event in enumerate(events):
        grouped.setdefault(event.session_id, []).append(index)
    allocated = list(events)
    with pg_pool().connection() as conn:
        for session_id, indexes in grouped.items():
            conn.execute(
                "INSERT INTO session_sequences (tenant_id, session_id, next_seq) "
                "VALUES (%s, %s, 0) ON CONFLICT (tenant_id, session_id) DO NOTHING",
                (tenant_id, session_id),
            )
            row = conn.execute(
                "SELECT next_seq FROM session_sequences "
                "WHERE tenant_id = %s AND session_id = %s FOR UPDATE",
                (tenant_id, session_id),
            ).fetchone()
            assert row is not None
            start = int(row[0])
            for offset, index in enumerate(indexes):
                allocated[index] = events[index].model_copy(update={"seq": start + offset})
            conn.execute(
                "UPDATE session_sequences SET next_seq = %s "
                "WHERE tenant_id = %s AND session_id = %s",
                (start + len(indexes), tenant_id, session_id),
            )
    return allocated


def _operation(attrs: dict[str, Any], span_name: str) -> str:
    explicit = attrs.get(GEN_AI_OPERATION)
    if explicit:
        return str(explicit)
    inference = str(attrs.get("openinference.span.kind", "")).lower()
    traceloop = str(attrs.get("traceloop.span.kind", "")).lower()
    request_type = str(attrs.get("llm.request.type", "")).lower()
    if inference == "tool" or traceloop == "tool":
        return "execute_tool"
    if inference in {"llm", "chat"} or traceloop == "llm" or request_type:
        return "chat"
    if inference in {"agent", "chain"} or traceloop in {"workflow", "task"}:
        return "invoke_agent"
    lowered = span_name.lower()
    if "tool" in lowered:
        return "execute_tool"
    if "llm" in lowered or "chat" in lowered:
        return "chat"
    return "invoke_agent"


def _event_type(operation: str, attrs: dict[str, Any]) -> str:
    openinference_kind = str(attrs.get("openinference.span.kind", "")).upper()
    if operation == "execute_tool" or openinference_kind == "TOOL":
        return "tool_call"
    if operation in {"chat", "generate_content", "text_completion"}:
        return "llm_call"
    return "agent_step"


def _credential_ref(attrs: dict[str, Any]) -> str | None:
    raw = _string(
        attrs.get("abx.credential.ref")
        or attrs.get("credential.ref")
        or attrs.get("auth.credential.fingerprint")
    )
    if not raw or not _FINGERPRINT.fullmatch(raw):
        return None
    return raw.removeprefix("aws:")


def _resource_refs(attrs: dict[str, Any]) -> list[str]:
    raw = attrs.get("abx.resource.refs") or attrs.get("resource.refs") or []
    values = raw if isinstance(raw, list) else [raw]
    return [_clean(value)[:1024] for value in values if value][:1024]


def _attributes(values: Any) -> dict[str, Any]:
    return {item.key: _any_value(item.value) for item in values}


def _any_value(value: AnyValue) -> Any:
    selected = value.WhichOneof("value")
    if selected == "array_value":
        return [_any_value(item) for item in value.array_value.values]
    if selected == "kvlist_value":
        return {item.key: _any_value(item.value) for item in value.kvlist_value.values}
    return getattr(value, selected) if selected else None


def _string(value: Any) -> str:
    return str(value) if value is not None else ""


def _clean(value: Any) -> str:
    cleaned, _rules = redact(_string(value))
    return cleaned


def link_observed_credentials(tenant_id: str, events: list[IngestEvent]) -> None:
    with pg_pool().connection() as conn:
        for event in events:
            fingerprint = event.credential_ref
            if not fingerprint:
                continue
            provider_kind = _provider_kind(fingerprint)
            if provider_kind is None:
                continue
            provider, kind = provider_kind
            agent = conn.execute(
                "INSERT INTO agents (tenant_id, name, framework, status, last_seen) "
                "VALUES (%s, %s, 'otel', 'active', now()) "
                "ON CONFLICT (tenant_id, name) DO UPDATE SET last_seen = now() RETURNING id",
                (tenant_id, event.agent_id),
            ).fetchone()
            credential = conn.execute(
                "INSERT INTO credentials "
                "(tenant_id, provider, kind, fingerprint, status, last_scanned) "
                "VALUES (%s, %s, %s, %s, 'active', now()) "
                "ON CONFLICT (tenant_id, provider, fingerprint) DO UPDATE SET "
                "last_scanned = now() RETURNING id",
                (tenant_id, provider, kind, fingerprint),
            ).fetchone()
            assert agent is not None and credential is not None
            conn.execute(
                "INSERT INTO agent_holds_credential (agent_id, credential_id, inferred_from) "
                "VALUES (%s, %s, 'traffic') ON CONFLICT (agent_id, credential_id) "
                "DO UPDATE SET inferred_from = 'traffic'",
                (agent[0], credential[0]),
            )


def _provider_kind(fingerprint: str) -> tuple[str, str] | None:
    if re.fullmatch(r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}", fingerprint):
        return "aws", "access_key"
    if fingerprint.startswith("pat:"):
        return "github", "fine_grained_pat"
    if fingerprint.startswith("deploykey:"):
        return "github", "deploy_key"
    if fingerprint.startswith("appinstall:"):
        return "github", "app_installation"
    return None
