from __future__ import annotations

import pytest
from abx_api.metering import decide_capture


def test_unlimited_plan_keeps_full_fidelity() -> None:
    decision = decide_capture(50, 10, None)
    assert decision.full_fidelity_payloads == 10
    assert decision.over_limit_payloads == 0
    assert decision.limit_state == "unlimited"


def test_batch_crossing_limit_degrades_only_overage() -> None:
    decision = decide_capture(8, 5, 10)
    assert decision.full_fidelity_payloads == 2
    assert decision.over_limit_payloads == 3
    assert decision.limit_state == "degraded"


def test_exhausted_limit_accepts_metadata_only_batch() -> None:
    decision = decide_capture(10, 3, 10)
    assert decision.full_fidelity_payloads == 0
    assert decision.over_limit_payloads == 3
    assert decision.limit_state == "degraded"


@pytest.mark.parametrize("current,batch,limit", [(-1, 1, None), (0, -1, None), (0, 1, 0)])
def test_invalid_usage_is_rejected(current: int, batch: int, limit: int | None) -> None:
    with pytest.raises(ValueError):
        decide_capture(current, batch, limit)
