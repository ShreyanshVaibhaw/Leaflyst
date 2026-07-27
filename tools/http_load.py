"""Real-network ingest load check for a running Leaflyst API.

Example:
  uv run python tools/http_load.py --base-url http://localhost:8000 \
    --rate 10000 --duration 60 --batch 200 --concurrency 4 \
    --tenant-id "$ABX_TENANT_ID" --verify

ABX_INGEST_TOKEN and, with --verify, ABX_ADMIN_KEY are read from the
environment so credentials do not need to appear in shell history. Use a
dedicated tenant: pre/post accepted-count verification assumes no other writer.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import httpx

MAX_CHAIN_SEQ = 9_223_372_036_854_775_807


@dataclass(frozen=True)
class Config:
    rate_per_minute: int
    duration_seconds: float
    batch_size: int
    payload_bytes: int
    concurrency: int
    tenant_id: str | None = None
    admin_key: str | None = None


@dataclass(frozen=True)
class Result:
    target_rate_per_minute: int
    requested: int
    accepted: int
    requests: int
    elapsed_seconds: float
    throughput_per_minute: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    request_errors: int
    request_error_rate: float
    event_error_rate: float
    chain_valid: bool | None
    chain_events_before: int | None
    chain_events_after: int | None
    accepted_count_matches: bool | None
    rate_target_met: bool

    @property
    def ok(self) -> bool:
        return (
            self.rate_target_met
            and self.request_errors == 0
            and self.accepted == self.requested
            and self.chain_valid is not False
            and self.accepted_count_matches is not False
        )


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _batch(count: int, payload_bytes: int, batch_number: int) -> dict[str, object]:
    timestamp = datetime.now(UTC).isoformat()
    session_id = f"http-load-{uuid.uuid4()}"
    payload = "x" * payload_bytes
    return {
        "events": [
            {
                "event_id": str(uuid.uuid4()),
                "agent_id": "http-load",
                "session_id": session_id,
                "seq": sequence,
                "ts": timestamp,
                "source": "mcp_tap",
                "event_type": "mcp_request",
                "operation": {
                    "name": f"load/batch/{batch_number}",
                    "outcome": "success",
                },
                "resource_refs": ["load:test"],
                "payload": payload,
            }
            for sequence in range(count)
        ]
    }


def _send(
    client: httpx.Client,
    token: str,
    body: dict[str, object],
    requested: int,
) -> tuple[float, int, bool]:
    started = time.perf_counter()
    try:
        response = client.post(
            "/v1/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json=body,
        )
        response.raise_for_status()
        body = response.json()
        accepted = body.get("accepted") if isinstance(body, dict) else None
        if not isinstance(accepted, int) or not 0 <= accepted <= requested:
            return time.perf_counter() - started, 0, False
        return time.perf_counter() - started, accepted, True
    except (httpx.HTTPError, ValueError):
        return time.perf_counter() - started, 0, False


def _verify(client: httpx.Client, tenant_id: str, admin_key: str) -> tuple[bool, int]:
    response = client.get(
        "/v1/chain/verify",
        headers={"X-Abx-Admin-Key": admin_key},
        params={"tenant_id": tenant_id, "from_chain_seq": 1, "to_chain_seq": MAX_CHAIN_SEQ},
    )
    response.raise_for_status()
    body = response.json()
    valid = body.get("valid") if isinstance(body, dict) else None
    events_checked = body.get("events_checked") if isinstance(body, dict) else None
    if not isinstance(valid, bool) or not isinstance(events_checked, int):
        raise ValueError("invalid chain verification response")
    return valid, events_checked


def run_load(client: httpx.Client, token: str, config: Config) -> Result:
    target = max(1, round(config.rate_per_minute / 60 * config.duration_seconds))
    before: int | None = None
    if config.tenant_id and config.admin_key:
        before_valid, before = _verify(client, config.tenant_id, config.admin_key)
        if not before_valid:
            raise RuntimeError("tenant chain is invalid before the load run")

    latencies: list[float] = []
    accepted = 0
    errors = 0
    submitted = 0
    batch_number = 0
    pending: set[Future[tuple[float, int, bool]]] = set()

    def collect(done: set[Future[tuple[float, int, bool]]]) -> None:
        nonlocal accepted, errors
        for future in done:
            latency, batch_accepted, success = future.result()
            latencies.append(latency * 1_000)
            accepted += batch_accepted
            errors += int(not success)

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
        while submitted < target:
            if len(pending) >= config.concurrency:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                collect(done)
            delay = started + submitted * 60 / config.rate_per_minute - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            count = min(config.batch_size, target - submitted)
            pending.add(
                pool.submit(
                    _send,
                    client,
                    token,
                    _batch(count, config.payload_bytes, batch_number),
                    count,
                )
            )
            submitted += count
            batch_number += 1
        if pending:
            collect(set(wait(pending).done))
    elapsed = time.perf_counter() - started
    throughput = accepted / elapsed * 60

    chain_valid: bool | None = None
    after: int | None = None
    count_matches: bool | None = None
    if config.tenant_id and config.admin_key:
        chain_valid, after = _verify(client, config.tenant_id, config.admin_key)
        count_matches = after - before == accepted if before is not None else None

    return Result(
        target_rate_per_minute=config.rate_per_minute,
        requested=target,
        accepted=accepted,
        requests=len(latencies),
        elapsed_seconds=elapsed,
        throughput_per_minute=throughput,
        latency_p50_ms=_percentile(latencies, 0.50),
        latency_p95_ms=_percentile(latencies, 0.95),
        latency_p99_ms=_percentile(latencies, 0.99),
        request_errors=errors,
        request_error_rate=errors / len(latencies),
        event_error_rate=(target - accepted) / target,
        chain_valid=chain_valid,
        chain_events_before=before,
        chain_events_after=after,
        accepted_count_matches=count_matches,
        rate_target_met=throughput >= config.rate_per_minute,
    )


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--rate", type=_positive, default=10_000, help="events per minute")
    parser.add_argument("--duration", type=_positive_float, default=60, help="seconds")
    parser.add_argument("--batch", type=_positive, default=200, help="events per request")
    parser.add_argument("--payload-bytes", type=int, default=256)
    parser.add_argument("--concurrency", type=_positive, default=4)
    parser.add_argument("--tenant-id", default=os.environ.get("ABX_TENANT_ID"))
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--timeout", type=_positive_float, default=30)
    args = parser.parse_args()
    token = os.environ.get("ABX_INGEST_TOKEN")
    admin_key = os.environ.get("ABX_ADMIN_KEY") if args.verify else None
    if not token:
        parser.error("ABX_INGEST_TOKEN is required")
    if args.payload_bytes < 0:
        parser.error("--payload-bytes must be at least 0")
    if args.batch > 100_000:
        parser.error("--batch cannot exceed the API limit of 100000")
    if args.verify and not (args.tenant_id and admin_key):
        parser.error("--verify requires --tenant-id/ABX_TENANT_ID and ABX_ADMIN_KEY")

    config = Config(
        rate_per_minute=args.rate,
        duration_seconds=args.duration,
        batch_size=args.batch,
        payload_bytes=args.payload_bytes,
        concurrency=args.concurrency,
        tenant_id=args.tenant_id,
        admin_key=admin_key,
    )
    with httpx.Client(
        base_url=args.base_url.rstrip("/"),
        timeout=args.timeout,
        limits=httpx.Limits(max_connections=args.concurrency),
    ) as client:
        result = run_load(client, token, config)
    print(json.dumps(asdict(result) | {"ok": result.ok}, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
