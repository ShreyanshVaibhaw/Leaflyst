"""OpenAI Agents SDK handoffs and A2A delegation capture.

Recording multi-agent delegation is the novel part: a gateway sees the traffic
that passes through it, but who handed work to whom, and what identity was
asserted at each hop, is what OWASP ASI03 (identity and privilege abuse in
delegation chains) and ASI07 (insecure inter-agent communication) are about.

The load-bearing decision under test: A2A advertises auth schemes through Agent
Cards but does NOT mandate how those cards are verified, so every peer identity
is recorded as a claim. Naming it verified would launder an unverified
assertion into evidence.
"""

from __future__ import annotations

from abx_api.normalize import normalize_export
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span


def _kv(key: str, value: str) -> KeyValue:
    return KeyValue(key=key, value=AnyValue(string_value=value))


def export(*spans: Span, service: str = "orchestrator") -> ExportTraceServiceRequest:
    return ExportTraceServiceRequest(resource_spans=[ResourceSpans(
        resource=Resource(attributes=[_kv("service.name", service)]),
        scope_spans=[ScopeSpans(spans=list(spans))],
    )])


def span(name: str, attrs: dict[str, str], *, start: int = 1) -> Span:
    return Span(
        name=name,
        trace_id=b"\x01" * 16,
        span_id=bytes([start]) * 8,
        start_time_unix_nano=start * 1_000_000_000,
        end_time_unix_nano=start * 1_000_000_000 + 5_000_000,
        attributes=[_kv(k, v) for k, v in attrs.items()],
    )


def refs(events: list) -> list[str]:
    return [ref.root for event in events for ref in event.resource_refs]


# -- OpenAI Agents SDK --------------------------------------------------------

def test_handoff_is_recorded_as_delegation_not_a_tool_call() -> None:
    """A handoff collapsed into execute_tool would lose the multi-agent edge
    that makes a delegation chain readable."""
    events = normalize_export(export(span("agent.handoff", {
        "openai.agent.name": "triage",
        "openai.agent.handoff.from": "triage",
        "openai.agent.handoff.to": "refunds",
    })))
    assert len(events) == 1
    assert events[0].event_type.value == "agent_step"
    assert events[0].agent_id == "triage"
    assert "abx:handoff-to:refunds" in refs(events)
    assert "abx:handoff-from:triage" in refs(events)


def test_openai_agent_name_identifies_the_agent() -> None:
    events = normalize_export(export(span("chat", {
        "openai.agent.name": "researcher",
        "gen_ai.request.model": "gpt-5",
    })))
    assert events[0].agent_id == "researcher"
    assert events[0].event_type.value == "llm_call"


# -- A2A ----------------------------------------------------------------------

def test_peer_identity_is_recorded_as_a_claim() -> None:
    """A2A does not mandate Agent Card verification, so an asserted identity is
    an assertion. The ref name has to carry that."""
    events = normalize_export(export(span("a2a.send_task", {
        "a2a.task.id": "task-77",
        "a2a.agent.name": "planner",
        "a2a.peer.agent.name": "billing-agent",
        "a2a.peer.asserted.identity": "spiffe://example.org/billing",
        "a2a.peer.auth.scheme": "oauth2",
        "a2a.agent.card.digest": "sha256:abc123",
    })))
    produced = refs(events)
    assert "abx:a2a-peer-claimed:billing-agent" in produced
    assert "abx:a2a-identity-claimed:spiffe://example.org/billing" in produced
    assert "abx:a2a-auth-scheme:oauth2" in produced
    assert "abx:a2a-card:sha256:abc123" in produced
    # Nothing may present the peer as verified.
    assert not any("verified" in ref for ref in produced)


def test_a2a_delegation_is_an_agent_step() -> None:
    events = normalize_export(export(span("a2a.send_task", {
        "a2a.task.id": "task-1", "a2a.peer.agent.name": "worker",
    })))
    assert events[0].event_type.value == "agent_step"


def test_a2a_context_groups_the_chain_into_one_session() -> None:
    """A delegation chain crossing agents must read as ONE session, or replay
    shows three unrelated fragments instead of a chain."""
    events = normalize_export(export(
        span("a2a.send_task", {
            "a2a.context.id": "ctx-9", "a2a.agent.name": "planner",
            "a2a.peer.agent.name": "billing",
        }, start=1),
        span("a2a.send_task", {
            "a2a.context.id": "ctx-9", "a2a.agent.name": "billing",
            "a2a.peer.agent.name": "ledger",
        }, start=2),
        span("a2a.receive_task", {
            "a2a.context.id": "ctx-9", "a2a.agent.name": "ledger",
        }, start=3),
    ))
    assert {event.session_id for event in events} == {"ctx-9"}
    assert [event.seq for event in events] == [0, 1, 2]
    assert [event.agent_id for event in events] == ["planner", "billing", "ledger"]

    hops = [ref for ref in refs(events) if ref.startswith("abx:a2a-peer-claimed:")]
    assert hops == ["abx:a2a-peer-claimed:billing", "abx:a2a-peer-claimed:ledger"]


def test_task_id_is_recorded_for_correlation() -> None:
    events = normalize_export(export(span("a2a.send_task", {"a2a.task.id": "t-42"})))
    assert "abx:a2a-task:t-42" in refs(events)


def test_ordinary_spans_get_no_delegation_refs() -> None:
    """A negative control: delegation refs on every span would make the signal
    meaningless."""
    events = normalize_export(export(span("chat", {
        "gen_ai.operation.name": "chat", "gen_ai.request.model": "claude-sonnet-5",
    })))
    assert not [ref for ref in refs(events) if ref.startswith(("abx:a2a", "abx:handoff"))]


def test_no_credential_material_is_captured_from_a2a_attributes() -> None:
    """The auth SCHEME is recorded; a bearer token never is."""
    events = normalize_export(export(span("a2a.send_task", {
        "a2a.task.id": "t-1",
        "a2a.peer.auth.scheme": "oauth2",
    })))
    produced = " ".join(refs(events))
    assert "oauth2" in produced
    assert "Bearer" not in produced
    assert events[0].payload is None
