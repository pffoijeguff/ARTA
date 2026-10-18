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


def test_child_deadline_is_narrower_than_parent_deadline() -> None:
    parent = ExecutionControl(timeout_seconds=2.0)
    child = parent.child(timeout_seconds=0.05)
    child_remaining = child.remaining_seconds
    parent_remaining = parent.remaining_seconds
    assert child_remaining is not None
    assert parent_remaining is not None
    # The child deadline is 0.05s from child creation, while the parent has ~2s left.
    # Using comfortably separated deadlines avoids comparing two moving clock reads.
    assert child_remaining < 0.1
    assert parent_remaining > 1.0
    assert child_remaining < parent_remaining


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), True, "5", 10**1000])
def test_execution_control_rejects_invalid_timeout_values(value) -> None:
    with pytest.raises(MissionError):
        ExecutionControl(timeout_seconds=value)
