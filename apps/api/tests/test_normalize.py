"""Schema-diverse OTLP normalization and live collector integration."""

from __future__ import annotations

from typing import Any

import psycopg
from abx_api import normalize
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client, get_payload
from conftest import requires_stack
from fastapi.testclient import TestClient
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue

pytestmark = requires_stack
client = TestClient(app)


def _value(value: Any) -> AnyValue:
    result = AnyValue()
    if isinstance(value, bool):
        result.bool_value = value
    elif isinstance(value, int):
        result.int_value = value
    elif isinstance(value, float):
        result.double_value = value
    elif isinstance(value, list):
        result.array_value.values.extend([_value(item) for item in value])
    elif isinstance(value, dict):
        result.kvlist_value.values.extend(
            [KeyValue(key=str(key), value=_value(item)) for key, item in value.items()]
        )
    else:
        result.string_value = str(value)
    return result


def _request(attributes: dict[str, Any], *, name: str = "chat model") -> ExportTraceServiceRequest:
    request = ExportTraceServiceRequest()
    resource_spans = request.resource_spans.add()
    resource_spans.resource.attributes.add(
        key="service.name", value=_value("third-party-agent")
    )
    scope_spans = resource_spans.scope_spans.add()
    scope_spans.scope.name = "test-instrumentation"
    span = scope_spans.spans.add()
    span.trace_id = b"\x01" * 16
    span.span_id = b"\x02" * 8
    span.name = name
    span.start_time_unix_nano = 1_800_000_000_000_000_000
    span.end_time_unix_nano = span.start_time_unix_nano + 25_000_000
    span.status.code = 1
    span.attributes.extend(
        [KeyValue(key=key, value=_value(value)) for key, value in attributes.items()]
    )
    return request


def test_current_otel_shape_normalizes_to_llm_event() -> None:
    request = _request(
        {
            normalize.GEN_AI_OPERATION: "chat",
            normalize.GEN_AI_PROVIDER: "openai",
            normalize.GEN_AI_REQUEST_MODEL: "gpt-4.1",
            normalize.GEN_AI_AGENT_ID: "support-agent",
            normalize.GEN_AI_INPUT_TOKENS: 12,
            normalize.GEN_AI_OUTPUT_TOKENS: 4,
            normalize.GEN_AI_INPUT_MESSAGES: '[{"role":"user"}]',
            "abx.credential.ref": "pat:4242",
            "abx.resource.refs": ["gh:repo:acme/support"],
        }
    )
    event = normalize.normalize_export(request)[0]
    assert event.agent_id == "support-agent"
    assert event.event_type.value == "llm_call"
    assert event.operation.provider == "openai"
    assert event.operation.target == "gpt-4.1"
    assert event.operation.duration_ms == 25
    assert event.credential_ref == "pat:4242"
    assert [ref.root for ref in event.resource_refs] == ["gh:repo:acme/support"]
    assert normalize.GEN_AI_INPUT_MESSAGES in (event.payload or "")


def test_legacy_openllmetry_and_openinference_shapes() -> None:
    legacy = normalize.normalize_export(
        _request(
            {
                normalize.GEN_AI_SYSTEM_LEGACY: "anthropic",
                normalize.GEN_AI_REQUEST_MODEL: "claude-sonnet",
                normalize.GEN_AI_PROMPT_TOKENS_LEGACY: 5,
                "traceloop.span.kind": "llm",
                "llm.request.type": "chat",
            }
        )
    )[0]
    assert legacy.event_type.value == "llm_call"
    assert legacy.operation.provider == "anthropic"

    openinference = normalize.normalize_export(
        _request(
            {
                "openinference.span.kind": "TOOL",
                "tool.name": "search_docs",
                "input.value": "query",
                "output.value": "result",
            },
            name="search_docs",
        )
    )[0]
    assert openinference.event_type.value == "tool_call"
    assert openinference.operation.target == "search_docs"
    assert "input.value" in (openinference.payload or "")


def test_otlp_endpoint_redacts_and_links_traffic_credential(
    tenant: tuple[str, str],
) -> None:
    tenant_id, token = tenant
    secret = "ghp_" + "a" * 36
    request = _request(
        {
            normalize.GEN_AI_OPERATION: "chat",
            normalize.GEN_AI_PROVIDER: "openai",
            normalize.GEN_AI_AGENT_ID: "runtime-agent",
            normalize.GEN_AI_INPUT_MESSAGES: f"use token {secret}",
            "abx.credential.ref": "pat:4242",
            "abx.resource.refs": [
                "postgresql://user:supersecretpassword@db.example/prod"
            ],
        },
        name="chat " + secret,
    )
    response = client.post(
        "/v1/otlp/traces",
        content=request.SerializeToString(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-protobuf",
        },
    )
    assert response.status_code == 200, response.text
    ExportTraceServiceResponse.FromString(response.content)

    result = ch_client().query(
        "SELECT payload_ref, redactions, credential_ref, op_name, resource_refs FROM events "
        "WHERE tenant_id = %(tenant)s ORDER BY chain_seq DESC LIMIT 1",
        parameters={"tenant": tenant_id},
    )
    payload_ref, redactions, credential_ref, op_name, resource_refs = result.result_rows[0]
    payload = get_payload(payload_ref)
    assert payload is not None and secret.encode() not in payload
    assert "github-token" in list(redactions)
    assert credential_ref == "pat:4242"
    assert secret not in op_name
    assert "supersecretpassword" not in str(resource_refs)

    with psycopg.connect(settings.pg_dsn) as conn:
        edge = conn.execute(
            "SELECT a.name, c.fingerprint, ahc.inferred_from "
            "FROM agent_holds_credential ahc "
            "JOIN agents a ON a.id = ahc.agent_id "
            "JOIN credentials c ON c.id = ahc.credential_id "
            "WHERE a.tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    assert edge == ("runtime-agent", "pat:4242", "traffic")


def test_otlp_endpoint_requires_write_only_token_and_protobuf() -> None:
    request = _request({normalize.GEN_AI_OPERATION: "chat"})
    no_token = client.post(
        "/v1/otlp/traces",
        content=request.SerializeToString(),
        headers={"Content-Type": "application/x-protobuf"},
    )
    assert no_token.status_code == 401
