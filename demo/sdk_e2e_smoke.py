"""Phase 5 exit check: real LangGraph callbacks -> OTLP -> redacted chain.

Run with ``uv run python demo/sdk_e2e_smoke.py`` while the dev data stack is
healthy. The script starts the API, creates a throwaway tenant, runs a graph
with a fake chat model and tool, and requires the hierarchy to arrive in under
60 seconds with a valid hash chain.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import TypedDict

import psycopg
from abx import instrument
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph

REPO = Path(__file__).resolve().parent.parent
API_PORT = 8322


class DemoState(TypedDict):
    value: int
    prompt: str


@tool
def increment(value: int) -> int:
    """Increment an integer."""
    return value + 1


def wait_http(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except Exception:
            time.sleep(0.5)
    raise TimeoutError(f"{url} not reachable")


def main() -> int:
    from abx_api.auth import new_ingest_token
    from abx_api.settings import settings
    from abx_api.store import ch_client, delete_payload, ensure_buckets

    ensure_buckets()
    tenant_id: str | None = None
    handler = None
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "abx_api.main:app", "--port", str(API_PORT)],
        cwd=str(REPO),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_http(f"http://127.0.0.1:{API_PORT}/healthz")
        token, token_hash = new_ingest_token()
        with psycopg.connect(settings.pg_dsn) as conn:
            row = conn.execute(
                "INSERT INTO tenants (name) VALUES ('sdk-smoke') RETURNING id"
            ).fetchone()
            assert row is not None
            tenant_id = str(row[0])
            conn.execute(
                "INSERT INTO ingest_tokens (tenant_id, token_hash, label) "
                "VALUES (%s, %s, 'sdk-smoke')",
                (tenant_id, token_hash),
            )
            conn.commit()

        model = FakeListChatModel(responses=["recorded"])

        def run_step(state: DemoState, config: RunnableConfig) -> dict[str, object]:
            value = increment.invoke({"value": state["value"]}, config=config)
            model.invoke(f"{state['prompt']} value={value}", config=config)
            return {"value": value}

        graph = StateGraph(DemoState)
        graph.add_node("run_step", run_step)
        graph.add_edge(START, "run_step")
        graph.add_edge("run_step", END)

        # Customer integration: create handler, pass callbacks, flush on exit.
        handler = instrument(
            agent_id="sdk-smoke-agent",
            endpoint=f"http://127.0.0.1:{API_PORT}/v1/otlp/traces",
            token=token,
            capture_content=True,
            credential_ref="pat:4242",
        )
        started = time.monotonic()
        graph.compile().invoke(
            {"value": 1, "prompt": "github_pat_" + "a" * 30},
            {"callbacks": [handler]},
        )
        assert handler.force_flush()

        deadline = started + 60
        rows: list[tuple] = []
        while time.monotonic() < deadline:
            rows = ch_client().query(
                "SELECT op_name, session_id, redactions, payload_ref, source FROM events "
                "WHERE tenant_id = %(tenant)s ORDER BY chain_seq",
                parameters={"tenant": tenant_id},
            ).result_rows
            names = [str(row[0]) for row in rows]
            if any(name.startswith("chat ") for name in names) and any(
                name == "execute_tool increment" for name in names
            ):
                break
            time.sleep(0.5)

        names = [str(row[0]) for row in rows]
        assert any(name.startswith("invoke_agent ") for name in names), names
        assert any(name.startswith("chat ") for name in names), names
        assert "execute_tool increment" in names
        assert len({str(row[1]) for row in rows}) == 1
        assert any("github-fine-grained-pat" in list(row[2]) for row in rows)
        assert {str(row[4]) for row in rows} == {"sdk_langgraph"}

        request = urllib.request.Request(
            f"http://127.0.0.1:{API_PORT}/v1/chain/verify?tenant_id={tenant_id}",
            headers={"X-Abx-Admin-Key": settings.admin_key},
        )
        with urllib.request.urlopen(request) as response:
            verdict = json.loads(response.read())
        assert verdict["valid"] is True, verdict
        elapsed = time.monotonic() - started
        print(
            f"OK: {len(rows)} hierarchical SDK events recorded, redacted, and verified "
            f"in {elapsed:.1f}s (<60s budget)"
        )

        for row in rows:
            if row[3]:
                delete_payload(str(row[3]))
        return 0
    finally:
        if handler is not None:
            handler.shutdown()
        api.terminate()
        try:
            api.wait(timeout=10)
        except subprocess.TimeoutExpired:
            api.kill()
        if tenant_id is not None:
            _cleanup_tenant(settings.pg_dsn, tenant_id)


def _cleanup_tenant(dsn: str, tenant_id: str) -> None:
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "DELETE FROM agent_holds_credential WHERE credential_id IN "
            "(SELECT id FROM credentials WHERE tenant_id = %s)",
            (tenant_id,),
        )
        for table in (
            "credentials", "agents", "metering_token_daily", "metering_daily", "tenant_plans",
            "ingest_tokens", "chain_heads"
        ):
            conn.execute(
                f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,)  # noqa: S608
            )
        conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))
        conn.commit()


if __name__ == "__main__":
    raise SystemExit(main())
