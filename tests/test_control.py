from __future__ import annotations

import time

import pytest

from arta.control import (
    CancellationToken,
    ExecutionCancelled,
    ExecutionControl,
    ExecutionDeadlineExceeded,
)
from arta.core import MissionError


def test_cancellation_token_is_idempotent_and_shared_across_child_controls() -> None:
    token = CancellationToken()
    parent = ExecutionControl(cancellation_token=token)
    child = parent.child(timeout_seconds=1.0)

    assert token.cancel()
    assert not token.cancel()
    assert token.is_cancelled
    with pytest.raises(ExecutionCancelled):
        child.raise_if_stopped()


def test_execution_deadline_uses_monotonic_elapsed_time() -> None:
    control = ExecutionControl(timeout_seconds=0.005)
    time.sleep(0.02)
    assert control.deadline_exceeded
    with pytest.raises(ExecutionDeadlineExceeded):
        control.raise_if_stopped()


def test_child_deadline_cannot_extend_parent_deadline() -> None:
    parent = ExecutionControl(timeout_seconds=0.03)
    child = parent.child(timeout_seconds=1.0)
    assert child.remaining_seconds is not None
    assert parent.remaining_seconds is not None
    assert child.remaining_seconds <= parent.remaining_seconds


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), True, "5", 10**1000])
def test_execution_control_rejects_invalid_timeout_values(value) -> None:
    with pytest.raises(MissionError):
        ExecutionControl(timeout_seconds=value)
