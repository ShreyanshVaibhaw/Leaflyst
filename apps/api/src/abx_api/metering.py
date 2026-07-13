"""Authoritative daily usage decisions for recording plan limits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

LimitState = Literal["unlimited", "within_limit", "degraded"]


@dataclass(frozen=True)
class CaptureDecision:
    """Per-token payload policy for one serialized ingest batch."""

    full_fidelity_payloads: int
    over_limit_payloads: int
    limit_state: LimitState


def decide_capture(
    current_captured_payloads: int,
    batch_payloads: int,
    daily_event_limit: int | None,
) -> CaptureDecision:
    """Allocate payload slots without letting one token affect another."""
    if current_captured_payloads < 0 or batch_payloads < 0:
        raise ValueError("usage counts cannot be negative")
    if daily_event_limit is not None and daily_event_limit < 1:
        raise ValueError("daily event limit must be positive")

    if daily_event_limit is None:
        return CaptureDecision(
            full_fidelity_payloads=batch_payloads,
            over_limit_payloads=0,
            limit_state="unlimited",
        )

    full_fidelity_payloads = min(
        batch_payloads, max(daily_event_limit - current_captured_payloads, 0)
    )
    over_limit_payloads = batch_payloads - full_fidelity_payloads
    return CaptureDecision(
        full_fidelity_payloads=full_fidelity_payloads,
        over_limit_payloads=over_limit_payloads,
        limit_state="degraded" if over_limit_payloads else "within_limit",
    )


def usage_state(events: int, daily_event_limit: int | None) -> LimitState:
    """Describe a previously committed daily count."""
    if events < 0:
        raise ValueError("usage count cannot be negative")
    if daily_event_limit is None:
        return "unlimited"
    if daily_event_limit < 1:
        raise ValueError("daily event limit must be positive")
    return "degraded" if events > daily_event_limit else "within_limit"
