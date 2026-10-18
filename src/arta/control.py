"""Cooperative execution deadlines and cancellation for ARTA tool handlers.

Python cannot safely force-stop an arbitrary synchronous callback. Context-aware
handlers should poll ExecutionControl; ordinary handlers are checked before and
after returning, and may therefore finish an external side effect after cancellation.
"""
from __future__ import annotations

import math
import threading
import time

from .core import MissionError


_MAX_TIMEOUT_SECONDS = 24 * 60 * 60


class ExecutionCancelled(MissionError):
    """Raised when a caller cancels an in-flight mission or tool."""


class ExecutionDeadlineExceeded(MissionError):
    """Raised when a mission or tool execution reaches its monotonic deadline."""


class CancellationToken:
    """Thread-safe, idempotent cancellation signal shared by related execution controls."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()

    def cancel(self) -> bool:
        """Set cancellation; return True only for the first request."""
        with self._lock:
            was_set = self._event.is_set()
            self._event.set()
            return not was_set

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise ExecutionCancelled("Execution was cancelled.")


class ExecutionControl:
    """A cancellation token plus an optional monotonic deadline."""

    def __init__(
        self,
        cancellation_token: CancellationToken | None = None,
        timeout_seconds: float | None = None,
        *,
        _deadline_at: float | None = None,
    ) -> None:
        if cancellation_token is not None and not isinstance(cancellation_token, CancellationToken):
            raise MissionError("cancellation_token must be a CancellationToken.")
        self._token = cancellation_token or CancellationToken()
        deadline = _deadline_at
        if timeout_seconds is not None:
            seconds = self._validate_timeout(timeout_seconds)
            candidate = time.monotonic() + seconds
            deadline = candidate if deadline is None else min(deadline, candidate)
        self._deadline_at = deadline

    @staticmethod
    def _validate_timeout(value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise MissionError("Timeout must be a finite positive number of seconds.")
        try:
            seconds = float(value)
        except (OverflowError, TypeError, ValueError):
            raise MissionError("Timeout must be a finite positive number of seconds.") from None
        if not math.isfinite(seconds) or seconds <= 0 or seconds > _MAX_TIMEOUT_SECONDS:
            raise MissionError("Timeout must be greater than zero and at most 24 hours.")
        return seconds

    @property
    def cancellation_token(self) -> CancellationToken:
        return self._token

    @property
    def remaining_seconds(self) -> float | None:
        if self._deadline_at is None:
            return None
        return max(0.0, self._deadline_at - time.monotonic())

    @property
    def deadline_exceeded(self) -> bool:
        return self._deadline_at is not None and time.monotonic() >= self._deadline_at

    def child(self, timeout_seconds: float | None = None) -> "ExecutionControl":
        """Create a narrower control that shares cancellation and cannot extend a parent deadline."""
        return ExecutionControl(
            cancellation_token=self._token,
            timeout_seconds=timeout_seconds,
            _deadline_at=self._deadline_at,
        )

    def raise_if_stopped(self) -> None:
        # Cancellation takes precedence when both controls are observed at once.
        self._token.raise_if_cancelled()
        if self.deadline_exceeded:
            raise ExecutionDeadlineExceeded("Execution deadline exceeded.")
