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
)


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


class MissionRunner:
    """Preflights a whole plan, executes only if all actions are authorized, then verifies."""

    def __init__(self, gateway: ToolGateway) -> None:
        self._gateway = gateway

    def run(
        self,
        mission: Mission,
        plan: MissionPlan,
        verifier: ActionVerifier,
        *,
        now: str | None = None,
    ) -> MissionRunReport:
        if mission.state not in {
            MissionState.CREATED,
            MissionState.PLANNED,
            MissionState.AWAITING_APPROVAL,
        }:
            raise MissionError("MissionRunner requires a new, planned, or approval-pending mission.")
        if not callable(verifier):
            raise MissionError("A verifier callback is required; tool output is not evidence by itself.")

        if mission.state is MissionState.CREATED:
            mission.transition(MissionState.PLANNED, "Mission plan accepted for preflight.")

        planned_criteria = {action.criterion for action in plan.actions}
        unknown_criteria = planned_criteria.difference(mission.acceptance_criteria)
        uncovered_criteria = set(mission.acceptance_criteria).difference(planned_criteria)
        if unknown_criteria or uncovered_criteria:
            mission.transition(MissionState.BLOCKED, "Plan criteria do not match mission acceptance criteria.")
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
            decision = self._gateway.authorize(
                action.tool_name,
                action.arguments_copy(),
                approval=action.approval,
                now=now,
            )
            if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
                pending.append(action.action_id)
            elif decision.effect is PolicyEffect.DENY:
                denied.append(action.action_id)

        # Preflight the entire plan before the first side effect. Never run earlier actions
        # while a later action is still unapproved or forbidden.
        if denied:
            mission.transition(MissionState.BLOCKED, "At least one planned action was denied by policy.")
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
            return MissionRunReport(
                mission_id=mission.mission_id,
                state=mission.state,
                completed=False,
                pending_action_ids=tuple(pending),
                reason="No actions ran. Approve the listed exact actions, then submit the plan again.",
            )

        mission.transition(MissionState.RUNNING, "All planned actions passed policy preflight.")
        results: list[tuple[PlannedAction, ToolResult]] = []
        for action in plan.actions:
            try:
                result = self._gateway.invoke(
                    mission,
                    action.tool_name,
                    action.arguments_copy(),
                    approval=action.approval,
                    now=now,
                )
            except MissionError:
                mission.transition(MissionState.FAILED, "A planned tool action failed or lost authorization.")
                return MissionRunReport(
                    mission_id=mission.mission_id,
                    state=mission.state,
                    completed=False,
                    tool_results=tuple(result for _, result in results),
                    failed_action_id=action.action_id,
                    reason="An action failed during execution; remaining actions were not run.",
                )
            results.append((action, result))

        mission.transition(MissionState.VERIFYING, "All planned tool calls returned results.")
        for action, result in results:
            try:
                outcome, summary = verifier(action, result)
                if not isinstance(outcome, EvidenceOutcome) or not isinstance(summary, str) or not summary.strip():
                    raise ValueError("Verifier result must contain an outcome and a non-empty summary.")
            except Exception as exc:
                # Keep the failure type visible without persisting potentially sensitive exception text.
                outcome = EvidenceOutcome.INCONCLUSIVE
                summary = f"Verifier raised {type(exc).__name__}."

            mission.add_evidence(Evidence(
                criterion=action.criterion,
                outcome=outcome,
                source_action_id=action.action_id,
                summary=summary.strip()[:1000],
                observed_at=_now(),
            ))

        completed = verify_mission(mission)
        return MissionRunReport(
            mission_id=mission.mission_id,
            state=mission.state,
            completed=completed,
            tool_results=tuple(result for _, result in results),
            reason="Mission verified." if completed else "Verification did not pass every required criterion.",
        )
