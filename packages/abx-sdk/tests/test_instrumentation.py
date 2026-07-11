"""LangGraph callback instrumentation and failure isolation."""

from __future__ import annotations

import json
from typing import TypedDict
from uuid import uuid4

from abx import instrument
from abx_sdk import conventions as sem
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.outputs import Generation, LLMResult
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


def test_hierarchical_agent_model_and_tool_spans_default_to_no_content() -> None:
    exporter = InMemorySpanExporter()
    handler = instrument(
        agent_id="billing-agent", exporter=exporter, credential_ref="pat:4242"
    )
    root, llm, tool = uuid4(), uuid4(), uuid4()

    handler.on_chain_start({"name": "billing"}, {"question": "secret"}, run_id=root)
    handler.on_llm_start(
        {"name": "ChatOpenAI"},
        ["hello"],
        run_id=llm,
        parent_run_id=root,
        metadata={"ls_model_name": "gpt-4.1"},
    )
    handler.on_llm_end(
        LLMResult(
            generations=[[Generation(text="answer")]],
            llm_output={
                "model_name": "gpt-4.1-2026-04-14",
                "token_usage": {"prompt_tokens": 7, "completion_tokens": 3},
            },
        ),
        run_id=llm,
        parent_run_id=root,
    )
    handler.on_tool_start(
        {"name": "lookup_invoice"}, "42", run_id=tool, parent_run_id=root
    )
    handler.on_tool_end("paid", run_id=tool, parent_run_id=root)
    handler.on_chain_end({"answer": "done"}, run_id=root)
    assert handler.force_flush()

    spans = {span.name: span for span in exporter.get_finished_spans()}
    agent = spans["invoke_agent billing"]
    model = spans["chat gpt-4.1"]
    tool_span = spans["execute_tool lookup_invoice"]
    assert model.parent is not None and model.parent.span_id == agent.context.span_id
    assert tool_span.parent is not None and tool_span.parent.span_id == agent.context.span_id
    assert model.attributes[sem.USAGE_INPUT_TOKENS] == 7
    assert model.attributes[sem.USAGE_OUTPUT_TOKENS] == 3
    assert model.attributes[sem.CONVERSATION_ID] == str(root)
    assert model.attributes["abx.credential.ref"] == "pat:4242"
    assert tool_span.attributes[sem.CONVERSATION_ID] == str(root)
    assert sem.INPUT_MESSAGES not in model.attributes
    assert sem.TOOL_CALL_ARGUMENTS not in tool_span.attributes
    handler.shutdown()


def test_content_capture_is_explicit_and_structured() -> None:
    exporter = InMemorySpanExporter()
    handler = instrument(
        agent_id="content-agent", exporter=exporter, capture_content=True
    )
    run_id = uuid4()
    handler.on_llm_start({"name": "model"}, ["hello"], run_id=run_id)
    handler.on_llm_end(
        LLMResult(generations=[[Generation(text="world")]]), run_id=run_id
    )
    assert handler.force_flush()
    span = exporter.get_finished_spans()[0]
    assert json.loads(span.attributes[sem.INPUT_MESSAGES])[0]["parts"][0]["content"] == "hello"
    assert json.loads(span.attributes[sem.OUTPUT_MESSAGES])[0]["parts"][0]["content"] == "world"
    handler.shutdown()


class DemoState(TypedDict):
    value: int


@tool
def increment(value: int) -> int:
    """Increment an integer."""
    return value + 1


def test_three_line_langgraph_integration_records_run() -> None:
    exporter = InMemorySpanExporter()
    handler = instrument(agent_id="graph-agent", exporter=exporter)
    model = FakeListChatModel(responses=["done"])

    def run_step(state: DemoState, config: RunnableConfig) -> dict[str, int]:
        value = increment.invoke({"value": state["value"]}, config=config)
        model.invoke(f"The value is {value}", config=config)
        return {"value": value}

    graph = StateGraph(DemoState)
    graph.add_node("run_step", run_step)
    graph.add_edge(START, "run_step")
    graph.add_edge("run_step", END)

    result = graph.compile().invoke({"value": 1}, {"callbacks": [handler]})
    assert result == {"value": 2}
    assert handler.force_flush()
    spans = exporter.get_finished_spans()
    assert spans
    assert all(span.attributes[sem.AGENT_ID] == "graph-agent" for span in spans)
    assert any(span.name.startswith("chat ") for span in spans)
    assert any(span.name == "execute_tool increment" for span in spans)
    handler.shutdown()


def test_callback_errors_never_escape_to_agent() -> None:
    exporter = InMemorySpanExporter()
    handler = instrument(agent_id="safe-agent", exporter=exporter, capture_content=True)
    # A malformed callback payload is ignored instead of breaking the run.
    handler.on_chain_start(None, {}, run_id=uuid4())  # type: ignore[arg-type]
    handler.on_tool_end(object(), run_id=uuid4())
    handler.on_llm_error(RuntimeError("backend down"), run_id=uuid4())
    handler.shutdown()


def test_secret_value_is_rejected_as_credential_reference() -> None:
    exporter = InMemorySpanExporter()
    try:
        instrument(
            agent_id="safe-agent",
            exporter=exporter,
            credential_ref="ghp_" + "a" * 36,
        )
    except ValueError as exc:
        assert "non-secret scanner fingerprint" in str(exc)
    else:
        raise AssertionError("secret-like credential_ref was accepted")


def test_standard_otel_environment_enables_content(monkeypatch) -> None:
    monkeypatch.setenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true")
    exporter = InMemorySpanExporter()
    handler = instrument(agent_id="env-agent", exporter=exporter)
    run_id = uuid4()
    handler.on_llm_start({"name": "model"}, ["captured"], run_id=run_id)
    handler.on_llm_end(
        LLMResult(generations=[[Generation(text="output")]]), run_id=run_id
    )
    assert handler.force_flush()
    assert sem.INPUT_MESSAGES in exporter.get_finished_spans()[0].attributes
    handler.shutdown()
