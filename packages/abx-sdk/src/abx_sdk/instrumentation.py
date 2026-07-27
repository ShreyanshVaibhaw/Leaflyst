"""LangChain/LangGraph callbacks emitting OpenTelemetry GenAI spans.

Callbacks never raise into the monitored agent. Export happens on the OTel
batch processor, so collector/network failure degrades recording only.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.trace import Span, SpanKind, Status, StatusCode, Tracer

from abx_sdk import conventions as sem

_FINGERPRINT = re.compile(
    r"^(?:(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|pat:[0-9]+|"
    r"deploykey:[^\s]{1,220}|appinstall:[0-9]+)$"
)


@dataclass
class _Run:
    span: Span
    operation: str
    root_run_id: UUID


class LeaflystCallbackHandler(BaseCallbackHandler):
    """A failure-isolated callback handler for LangChain and LangGraph."""

    raise_error = False

    def __init__(
        self,
        tracer: Tracer,
        provider: TracerProvider,
        *,
        agent_id: str,
        provider_name: str = "langchain",
        capture_content: bool = False,
        credential_ref: str | None = None,
    ) -> None:
        self._tracer = tracer
        self._provider = provider
        self.agent_id = agent_id
        self.provider_name = provider_name
        self.capture_content = capture_content
        self.credential_ref = credential_ref
        self._runs: dict[UUID, _Run] = {}
        self._lock = threading.RLock()

    def _start(
        self,
        run_id: UUID,
        parent_run_id: UUID | None,
        operation: str,
        name: str,
        kind: SpanKind,
        attributes: dict[str, str | int | bool],
    ) -> Span:
        with self._lock:
            parent = self._runs.get(parent_run_id) if parent_run_id else None
            context = trace.set_span_in_context(parent.span) if parent else None
            root_run_id = parent.root_run_id if parent else run_id
            attributes[sem.CONVERSATION_ID] = str(root_run_id)
            span = self._tracer.start_span(name, context=context, kind=kind, attributes=attributes)
            self._runs[run_id] = _Run(
                span=span, operation=operation, root_run_id=root_run_id
            )
            return span

    def _finish(
        self,
        run_id: UUID,
        *,
        error: BaseException | None = None,
        attributes: dict[str, str | int | bool] | None = None,
    ) -> None:
        with self._lock:
            run = self._runs.pop(run_id, None)
        if run is None:
            return
        if attributes:
            for key, value in attributes.items():
                run.span.set_attribute(key, value)
        if error is not None:
            run.span.record_exception(error)
            run.span.set_attribute("error.type", type(error).__name__)
            run.span.set_status(Status(StatusCode.ERROR, str(error)[:512]))
        else:
            run.span.set_status(Status(StatusCode.OK))
        run.span.end()

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            serialized = serialized or {}
            name = _name(serialized, kwargs) or self.agent_id
            attrs = self._base_attributes(sem.INVOKE_AGENT)
            attrs[sem.AGENT_NAME] = name
            if self.capture_content:
                attrs[sem.INPUT_MESSAGES] = _messages_json([("user", inputs)])
            self._start(
                run_id, parent_run_id, sem.INVOKE_AGENT,
                f"{sem.INVOKE_AGENT} {name}", SpanKind.INTERNAL, attrs,
            )
        except Exception:
            return

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            attrs: dict[str, str | int | bool] | None = (
                {sem.OUTPUT_MESSAGES: _messages_json([("assistant", outputs)])}
                if self.capture_content else None
            )
            self._finish(run_id, attributes=attrs)
        except Exception:
            return

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._finish(run_id, error=error)
        except Exception:
            return

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            serialized = serialized or {}
            model = _model(serialized, metadata, kwargs)
            attrs = self._base_attributes(sem.CHAT)
            if (metadata or {}).get("ls_provider"):
                attrs[sem.PROVIDER_NAME] = str((metadata or {})["ls_provider"])
            attrs[sem.REQUEST_MODEL] = model
            if self.capture_content:
                pairs = [
                    (_message_role(message), getattr(message, "content", str(message)))
                    for batch in messages
                    for message in batch
                ]
                attrs[sem.INPUT_MESSAGES] = _messages_json(pairs)
            self._start(
                run_id, parent_run_id, sem.CHAT,
                f"{sem.CHAT} {model}", SpanKind.CLIENT, attrs,
            )
        except Exception:
            return

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            serialized = serialized or {}
            model = _model(serialized, metadata, kwargs)
            attrs = self._base_attributes(sem.CHAT)
            if (metadata or {}).get("ls_provider"):
                attrs[sem.PROVIDER_NAME] = str((metadata or {})["ls_provider"])
            attrs[sem.REQUEST_MODEL] = model
            if self.capture_content:
                attrs[sem.INPUT_MESSAGES] = _messages_json([("user", p) for p in prompts])
            self._start(
                run_id, parent_run_id, sem.CHAT,
                f"{sem.CHAT} {model}", SpanKind.CLIENT, attrs,
            )
        except Exception:
            return

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            attrs = _usage_attributes(response)
            response_model = _response_model(response)
            if response_model:
                attrs[sem.RESPONSE_MODEL] = response_model
            if self.capture_content:
                attrs[sem.OUTPUT_MESSAGES] = _messages_json(
                    [("assistant", value) for value in _generation_texts(response)]
                )
            self._finish(run_id, attributes=attrs)
        except Exception:
            return

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._finish(run_id, error=error)
        except Exception:
            return

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            serialized = serialized or {}
            tool = _name(serialized, kwargs) or "tool"
            attrs = self._base_attributes(sem.EXECUTE_TOOL)
            attrs[sem.TOOL_NAME] = tool
            if self.capture_content:
                attrs[sem.TOOL_CALL_ARGUMENTS] = _json(inputs if inputs is not None else input_str)
            self._start(
                run_id, parent_run_id, sem.EXECUTE_TOOL,
                f"{sem.EXECUTE_TOOL} {tool}", SpanKind.INTERNAL, attrs,
            )
        except Exception:
            return

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            attrs: dict[str, str | int | bool] | None = (
                {sem.TOOL_CALL_RESULT: _json(output)} if self.capture_content else None
            )
            self._finish(run_id, attributes=attrs)
        except Exception:
            return

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._finish(run_id, error=error)
        except Exception:
            return

    def _base_attributes(self, operation: str) -> dict[str, str | int | bool]:
        attributes: dict[str, str | int | bool] = {
            sem.OPERATION_NAME: operation,
            sem.PROVIDER_NAME: self.provider_name,
            sem.AGENT_ID: self.agent_id,
        }
        if self.credential_ref:
            attributes["abx.credential.ref"] = self.credential_ref
        return attributes

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        try:
            return self._provider.force_flush(timeout_millis)
        except Exception:
            return False

    def shutdown(self) -> None:
        try:
            self._provider.shutdown()
        except Exception:
            return


def instrument(
    *,
    agent_id: str,
    endpoint: str | None = None,
    token: str | None = None,
    capture_content: bool | None = None,
    provider_name: str = "langchain",
    credential_ref: str | None = None,
    exporter: SpanExporter | None = None,
) -> LeaflystCallbackHandler:
    """Create the callback handler used in a LangGraph ``callbacks`` list."""
    endpoint = endpoint or os.environ.get(
        "ABX_OTLP_ENDPOINT", "http://localhost:8000/v1/otlp/traces"
    )
    token = token or os.environ.get("ABX_INGEST_TOKEN", "")
    credential_ref = credential_ref or os.environ.get("ABX_CREDENTIAL_REF")
    if credential_ref and not _FINGERPRINT.fullmatch(credential_ref):
        raise ValueError("credential_ref must be a non-secret scanner fingerprint")
    if exporter is None:
        if not token:
            raise ValueError("ABX_INGEST_TOKEN or token= is required")
        exporter = OTLPSpanExporter(
            endpoint=endpoint,
            headers={"Authorization": f"Bearer {token}"},
        )
    if capture_content is None:
        capture_content = os.environ.get(
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "false"
        ).lower() in {"1", "true", "yes"}
    resource = Resource.create(
        {
            "service.name": agent_id,
            "abx.agent.id": agent_id,
            "abx.source": "sdk_langgraph",
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    tracer = provider.get_tracer("abx-sdk", "0.1.0", schema_url=sem.SCHEMA_URL)
    return LeaflystCallbackHandler(
        tracer,
        provider,
        agent_id=agent_id,
        provider_name=provider_name,
        capture_content=capture_content,
        credential_ref=credential_ref,
    )


def _name(serialized: dict[str, Any], kwargs: dict[str, Any]) -> str | None:
    value = serialized.get("name") or kwargs.get("name")
    if value:
        return str(value)
    identifier = serialized.get("id")
    if isinstance(identifier, list) and identifier:
        return str(identifier[-1])
    return None


def _model(
    serialized: dict[str, Any], metadata: dict[str, Any] | None, kwargs: dict[str, Any]
) -> str:
    invocation = kwargs.get("invocation_params")
    candidates: list[Any] = [
        (metadata or {}).get("ls_model_name"),
        invocation.get("model") if isinstance(invocation, dict) else None,
        invocation.get("model_name") if isinstance(invocation, dict) else None,
        serialized.get("model"),
        serialized.get("model_name"),
        _name(serialized, kwargs),
    ]
    return next((str(v) for v in candidates if v), "unknown")


def _message_role(message: Any) -> str:
    role = getattr(message, "type", None) or getattr(message, "role", None) or "user"
    return "assistant" if str(role) in {"ai", "assistant"} else str(role)


def _json(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"), ensure_ascii=False)


def _messages_json(messages: list[tuple[str, Any]]) -> str:
    return _json([
        {
            "role": role,
            "parts": [{"type": "text", "content": _content_text(content)}],
        }
        for role, content in messages
    ])


def _content_text(content: Any) -> str:
    return content if isinstance(content, str) else _json(content)


def _usage_attributes(response: Any) -> dict[str, str | int | bool]:
    output = getattr(response, "llm_output", None) or {}
    usage = output.get("token_usage") or output.get("usage") or {}
    attrs: dict[str, str | int | bool] = {}
    input_tokens = usage.get("prompt_tokens") or usage.get("input_tokens")
    output_tokens = usage.get("completion_tokens") or usage.get("output_tokens")
    if isinstance(input_tokens, int):
        attrs[sem.USAGE_INPUT_TOKENS] = input_tokens
    if isinstance(output_tokens, int):
        attrs[sem.USAGE_OUTPUT_TOKENS] = output_tokens
    return attrs


def _response_model(response: Any) -> str | None:
    output = getattr(response, "llm_output", None) or {}
    value = output.get("model_name") or output.get("model")
    return str(value) if value else None


def _generation_texts(response: Any) -> list[Any]:
    values: list[Any] = []
    for batch in getattr(response, "generations", []) or []:
        for generation in batch:
            message = getattr(generation, "message", None)
            values.append(getattr(message, "content", None) or getattr(generation, "text", ""))
    return values
