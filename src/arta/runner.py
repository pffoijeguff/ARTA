"""Small end-to-end coordinator for the initial ARTA mission-kernel slice.

It only orchestrates already-registered in-process tools. It does not call an LLM,
perform host automation, or turn tool output into evidence without an explicit verifier.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .core import (
    Approval,
    Evidence,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    PolicyEffect,
    ToolGateway,
    ToolResult,
    _normalized_arguments,
    _now,
    verify_mission,
    fingerprint_action,
)

from .persistence import SQLiteMissionStore, StoreError


@dataclass(frozen=True)
class PlannedAction:
    """An immutable snapshot of one planned tool call and its required criterion."""

    action_id: str
    tool_name: str
    criterion: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    approval: Approval | None = None
    _arguments_json: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.action_id, "Action id"),
            (self.tool_name, "Tool name"),
            (self.criterion, "Acceptance criterion"),
        ):
            if not isinstance(value, str) or not value.strip():
                raise MissionError(f"{label} must be a non-empty string.")
        try:
            normalized = _normalized_arguments(self.arguments)
            serialized = json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (ValueError, TypeError):
            raise MissionError("Planned action arguments must be valid JSON.") from None
        object.__setattr__(self, "action_id", self.action_id.strip())
        object.__setattr__(self, "tool_name", self.tool_name.strip())
        object.__setattr__(self, "criterion", self.criterion.strip())
        object.__setattr__(self, "_arguments_json", serialized)

    def arguments_copy(self) -> dict[str, Any]:
        """Return a fresh object from the validated planning-time snapshot."""
        return json.loads(self._arguments_json)


@dataclass(frozen=True)
class MissionPlan:
    actions: tuple[PlannedAction, ...]

    def __post_init__(self) -> None:
        actions = tuple(self.actions)
        if not actions:
            raise MissionError("A mission plan must contain at least one action.")
        if not all(isinstance(action, PlannedAction) for action in actions):
            raise MissionError("A mission plan may contain only PlannedAction records.")
        ids = [action.action_id for action in actions]
        if len(set(ids)) != len(ids):
            raise MissionError("Planned action ids must be unique.")
        object.__setattr__(self, "actions", actions)


ActionVerifier = Callable[[PlannedAction, ToolResult], tuple[EvidenceOutcome, str]]


@dataclass(frozen=True)
class MissionRunReport:
    mission_id: str
    state: MissionState
    completed: bool
    tool_results: tuple[ToolResult, ...] = ()
    pending_action_ids: tuple[str, ...] = ()
    denied_action_ids: tuple[str, ...] = ()
    failed_action_id: str | None = None
    reason: str = ""


from .persistence import SQLiteMissionStore, StoreError


class MissionRunner:
    """Preflights, executes, verifies, and optionally checkpoints a mission in SQLite."""

    def __init__(
        self,
        gateway: ToolGateway,
        store: SQLiteMissionStore | None = None,
    ) -> None:
        self._gateway = gateway
        self._store = store

    def _checkpoint(self, mission: Mission) -> None:
        if self._store is not None:
            self._store.save_mission(mission)

    def _current_approval(self, action: PlannedAction) -> Approval | None:
        if self._store is None or action.approval is None:
            return action.approval
        current = self._store.get_approval(action.approval.approval_id)
        if current is None:
            raise StoreError("A plan-supplied approval is not present in the persistent approval store.")
        return current

    def run(
        self,
        mission: Mission,
        plan: MissionPlan,
        verifier: ActionVerifier,
    ) -> MissionRunReport:
        if mission.state not in {
            MissionState.CREATED,
            MissionState.PLANNED,
            MissionState.AWAITING_APPROVAL,
        }:
            raise MissionError("MissionRunner requires a new, planned, or approval-pending mission.")
        if not callable(verifier):
            raise MissionError("A verifier callback is required; tool output is not evidence by itself.")

        # Save the starting point first. The store refuses a separately reconstructed
        # in-memory mission whose audit prefix diverges from the persisted history.
        self._checkpoint(mission)
        if mission.state is MissionState.CREATED:
            mission.transition(MissionState.PLANNED, "Mission plan accepted for preflight.")
            self._checkpoint(mission)

        planned_criteria = {action.criterion for action in plan.actions}
        unknown_criteria = planned_criteria.difference(mission.acceptance_criteria)
        uncovered_criteria = set(mission.acceptance_criteria).difference(planned_criteria)
        if unknown_criteria or uncovered_criteria:
            mission.transition(MissionState.BLOCKED, "Plan criteria do not match mission acceptance criteria.")
            self._checkpoint(mission)
            return MissionRunReport(
                mission_id=mission.mission_id,
                state=mission.state,
                completed=False,
                denied_action_ids=tuple(
                    action.action_id for action in plan.actions if action.criterion in unknown_criteria
                ),
                reason="Plan criteria do not exactly cover the mission acceptance criteria.",
            )

        pending: list[str] = []
        denied: list[str] = []
        for action in plan.actions:
            approval = self._current_approval(action)
            decision = self._gateway.authorize(
                action.tool_name,
                action.arguments_copy(),
                approval=approval,
            )
            if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
                pending.append(action.action_id)
            elif decision.effect is PolicyEffect.DENY:
                denied.append(action.action_id)

        # Preflight the whole plan before any handler can run.
        if denied:
            mission.transition(MissionState.BLOCKED, "At least one planned action was denied by policy.")
            self._checkpoint(mission)
            return MissionRunReport(
                mission_id=mission.mission_id,
                state=mission.state,
                completed=False,
                denied_action_ids=tuple(denied),
                reason="One or more planned actions were denied by policy; no tool was executed.",
            )
        if pending:
            if mission.state is MissionState.PLANNED:
                mission.transition(MissionState.AWAITING_APPROVAL, "Plan contains actions awaiting approval.")
            self._checkpoint(mission)
            return MissionRunReport(
                mission_id=mission.mission_id,
                state=mission.state,
                completed=False,
                pending_action_ids=tuple(pending),
                reason="No actions ran. Approve the listed exact actions, then submit the plan again.",
            )

        mission.transition(MissionState.RUNNING, "All planned actions passed policy preflight.")
        self._checkpoint(mission)
        results: list[tuple[PlannedAction, ToolResult]] = []
        for action in plan.actions:
            # Re-read a stored approval immediately before starting this action so an
            # already persisted revocation is respected instead of a stale plan object.
            approval = self._current_approval(action)
            decision = self._gateway.authorize(
                action.tool_name,
                action.arguments_copy(),
                approval=approval,
            )
            if decision.effect is not PolicyEffect.ALLOW:
                mission.record("mission.action_recheck_denied", {
                    "action_id": action.action_id,
                    "tool": action.tool_name,
                    "effect": decision.effect.value,
                    "reason": decision.reason,
                })
                mission.transition(MissionState.BLOCKED, "An action failed its final authorization check.")
                self._checkpoint(mission)
                return MissionRunReport(
                    mission_id=mission.mission_id,
                    state=mission.state,
                    completed=False,
                    tool_results=tuple(result for _, result in results),
                    denied_action_ids=(action.action_id,),
                    failed_action_id=action.action_id,
                    reason="Final authorization failed; this and later actions were not invoked.",
                )

            fingerprint = fingerprint_action(action.tool_name, action.arguments_copy())
            if self._store is not None:
                self._store.record_action_event(
                    mission.mission_id, action.action_id, action.tool_name, fingerprint, "prepared"
                )
                self._store.record_action_event(
                    mission.mission_id, action.action_id, action.tool_name, fingerprint, "started"
                )
            try:
                result = self._gateway.invoke(
                    mission,
                    action.tool_name,
                    action.arguments_copy(),
                    approval=approval,
                )
            except MissionError as exc:
                if self._store is not None:
                    # A callback can fail after a partial external effect. Marking this
                    # as unknown is safer than pretending retry is automatically safe.
                    self._store.record_action_event(
                        mission.mission_id,
                        action.action_id,
                        action.tool_name,
                        fingerprint,
                        "unknown",
                        error_type=type(exc).__name__,
                    )
                mission.transition(MissionState.FAILED, "A planned tool action failed or lost authorization.")
                self._checkpoint(mission)
                return MissionRunReport(
                    mission_id=mission.mission_id,
                    state=mission.state,
                    completed=False,
                    tool_results=tuple(result for _, result in results),
                    failed_action_id=action.action_id,
                    reason="An action failed during execution; its external effect may be uncertain, and later actions were not run.",
                )
            if self._store is not None:
                self._store.record_action_event(
                    mission.mission_id,
                    action.action_id,
                    action.tool_name,
                    fingerprint,
                    "succeeded",
                    result=result.output,
                )
            results.append((action, result))
            self._checkpoint(mission)

        mission.transition(MissionState.VERIFYING, "All planned tool calls returned results.")
        self._checkpoint(mission)
        for action, result in results:
            try:
                outcome, summary = verifier(action, result)
                if not isinstance(outcome, EvidenceOutcome) or not isinstance(summary, str) or not summary.strip():
                    raise ValueError("Verifier result must contain an outcome and a non-empty summary.")
            except Exception as exc:
                outcome = EvidenceOutcome.INCONCLUSIVE
                summary = f"Verifier raised {type(exc).__name__}."

            mission.add_evidence(Evidence(
                criterion=action.criterion,
                outcome=outcome,
                source_action_id=action.action_id,
                summary=summary.strip()[:1000],
                observed_at=_now(),
            ))
            self._checkpoint(mission)

        completed = verify_mission(mission)
        self._checkpoint(mission)
        return MissionRunReport(
            mission_id=mission.mission_id,
            state=mission.state,
            completed=completed,
            tool_results=tuple(result for _, result in results),
            reason="Mission verified." if completed else "Verification did not pass every required criterion.",
        )
