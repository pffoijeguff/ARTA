"""Small end-to-end coordinator for the initial ARTA mission-kernel slice.

It only orchestrates already-registered in-process tools. It does not call an LLM,
perform host automation, or turn tool output into evidence without an explicit verifier.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .core import (
    MAX_TOOL_INVOCATIONS_PER_MISSION,
    Approval,
    Evidence,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    PolicyDecision,
    PolicyEffect,
    ToolGateway,
    ToolResult,
    _normalized_arguments,
    _now,
    verify_mission,
    fingerprint_action,
)
from .control import CancellationToken, ExecutionCancelled, ExecutionControl, ExecutionDeadlineExceeded
from .persistence import SQLiteMissionStore, StoreError


@dataclass(frozen=True)
class MissionRecoveryReport:
    """A conservative post-restart reconciliation result; never implies automatic resumption."""

    mission_id: str
    previous_state: MissionState
    state: MissionState
    recovered: bool
    requires_human_review: bool
    resolved_before_start_action_ids: tuple[str, ...] = ()
    uncertain_action_ids: tuple[str, ...] = ()
    reason: str = ""


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
        if len(actions) > MAX_TOOL_INVOCATIONS_PER_MISSION:
            raise MissionError(
                f"A mission plan may contain at most {MAX_TOOL_INVOCATIONS_PER_MISSION} actions."
            )
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
    """Preflights, executes, verifies, and optionally persists a mission."""

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

    def recover_interrupted_mission(self, mission_id: str) -> MissionRecoveryReport | None:
        """Conservatively reconcile a persisted mission after restart.

        This method never replays a tool call. A "prepared" action is known not to have
        reached the handler because the runner records "started" before calling it. A
        "started" action is ambiguous after process loss and becomes "unknown". Since the
        plan and raw tool results are intentionally not persisted, any non-terminal mission
        is blocked for human review instead of being resumed speculatively.
        """
        if self._store is None:
            raise MissionError("Restart recovery requires a configured SQLiteMissionStore.")
        if not isinstance(mission_id, str) or not mission_id.strip():
            raise MissionError("Mission id must be a non-empty string.")

        mission = self._store.load_mission(mission_id.strip())
        if mission is None:
            return None
        previous_state = mission.state
        terminal_states = {
            MissionState.COMPLETED,
            MissionState.BLOCKED,
            MissionState.FAILED,
            MissionState.CANCELLED,
        }
        if previous_state in terminal_states:
            existing_uncertain = tuple(
                row["action_id"]
                for row in self._store.unresolved_actions(mission.mission_id)
            )
            return MissionRecoveryReport(
                mission_id=mission.mission_id,
                previous_state=previous_state,
                state=mission.state,
                recovered=False,
                requires_human_review=bool(existing_uncertain),
                uncertain_action_ids=existing_uncertain,
                reason=(
                    "Mission is already terminal; no state was changed. Uncertain actions, if any, "
                    "remain available for explicit review."
                ),
            )

        resolved_before_start: list[str] = []
        for row in self._store.action_journal(mission.mission_id):
            if row["status"] == "prepared":
                self._store.record_action_event(
                    mission.mission_id,
                    row["action_id"],
                    row["tool_name"],
                    row["action_fingerprint"],
                    "failed",
                    error_type="ProcessInterruptedBeforeStart",
                )
                resolved_before_start.append(row["action_id"])
            elif row["status"] == "started":
                self._store.record_action_event(
                    mission.mission_id,
                    row["action_id"],
                    row["tool_name"],
                    row["action_fingerprint"],
                    "unknown",
                    error_type="ProcessRestartDuringAction",
                )

        unresolved = tuple(
            row["action_id"]
            for row in self._store.unresolved_actions(mission.mission_id)
        )
        reason = (
            "Process restart detected. The stored plan and raw tool results are not sufficient "
            "for safe automatic resumption. Reconcile any uncertain external effects, then create "
            "a new mission or explicitly re-plan."
        )
        mission.record("mission.recovery_required", {
            "previous_state": previous_state.value,
            "resolved_before_start_action_ids": resolved_before_start,
            "uncertain_action_ids": list(unresolved),
            "automatic_resume": False,
        })
        mission.transition(MissionState.BLOCKED, reason)
        self._checkpoint(mission)
        return MissionRecoveryReport(
            mission_id=mission.mission_id,
            previous_state=previous_state,
            state=mission.state,
            recovered=True,
            requires_human_review=True,
            resolved_before_start_action_ids=tuple(resolved_before_start),
            uncertain_action_ids=unresolved,
            reason=reason,
        )

    def _stop_report(
        self,
        mission: Mission,
        control: ExecutionControl,
        *,
        results: list[tuple[PlannedAction, ToolResult]] | None = None,
        action_id: str | None = None,
    ) -> MissionRunReport | None:
        try:
            control.raise_if_stopped()
        except ExecutionCancelled:
            return self._terminal_report(
                mission,
                MissionState.CANCELLED,
                "Mission was cancelled before the next execution boundary.",
                results=results,
                action_id=action_id,
            )
        except ExecutionDeadlineExceeded:
            return self._terminal_report(
                mission,
                MissionState.FAILED,
                "Mission deadline expired before the next execution boundary.",
                results=results,
                action_id=action_id,
            )
        return None

    def _terminal_report(
        self,
        mission: Mission,
        target: MissionState,
        reason: str,
        *,
        results: list[tuple[PlannedAction, ToolResult]] | None = None,
        action_id: str | None = None,
    ) -> MissionRunReport:
        if mission.state not in {
            MissionState.COMPLETED, MissionState.BLOCKED, MissionState.FAILED, MissionState.CANCELLED,
        }:
            mission.transition(target, reason)
        self._checkpoint(mission)
        return MissionRunReport(
            mission_id=mission.mission_id,
            state=mission.state,
            completed=False,
            tool_results=tuple(result for _, result in (results or [])),
            failed_action_id=action_id,
            reason=reason,
        )

    def _journal_unknown(
        self,
        mission: Mission,
        action: PlannedAction,
        fingerprint: str,
        error_type: str,
    ) -> None:
        if self._store is not None:
            self._store.record_action_event(
                mission.mission_id,
                action.action_id,
                action.tool_name,
                fingerprint,
                "unknown",
                error_type=error_type,
            )

    def run(
        self,
        mission: Mission,
        plan: MissionPlan,
        verifier: ActionVerifier,
        *,
        cancellation_token: CancellationToken | None = None,
        timeout_seconds: float | None = None,
    ) -> MissionRunReport:
        if mission.state not in {
            MissionState.CREATED,
            MissionState.PLANNED,
            MissionState.AWAITING_APPROVAL,
        }:
            raise MissionError("MissionRunner requires a new, planned, or approval-pending mission.")
        if not callable(verifier):
            raise MissionError("A verifier callback is required; tool output is not evidence by itself.")
        mission_control = ExecutionControl(
            cancellation_token=cancellation_token,
            timeout_seconds=timeout_seconds,
        )

        # Persist the starting point before planning; never accept a mismatched audit prefix.
        self._checkpoint(mission)
        stopped = self._stop_report(mission, mission_control)
        if stopped is not None:
            return stopped
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

        pending_actions: list[tuple[PlannedAction, PolicyDecision]] = []
        denied: list[str] = []
        seen_approval_ids: set[str] = set()
        for action in plan.actions:
            stopped = self._stop_report(mission, mission_control)
            if stopped is not None:
                return stopped
            approval = self._current_approval(action)
            if approval is not None:
                if approval.approval_id in seen_approval_ids:
                    denied.append(action.action_id)
                    continue
                seen_approval_ids.add(approval.approval_id)
            decision = self._gateway.authorize(
                action.tool_name,
                action.arguments_copy(),
                approval=approval,
            )
            if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
                pending_actions.append((action, decision))
            elif decision.effect is PolicyEffect.DENY:
                denied.append(action.action_id)

        pending = [action.action_id for action, _decision in pending_actions]

        stopped = self._stop_report(mission, mission_control)
        if stopped is not None:
            return stopped
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
            for action, decision in pending_actions:
                fingerprint = decision.action_fingerprint or ""
                if not self._gateway._has_pending_approval(mission, action.tool_name, fingerprint):
                    mission.record("tool.approval_requested", {
                        "action_id": action.action_id,
                        "tool": action.tool_name,
                        "action_fingerprint": fingerprint,
                        "reason": decision.reason,
                    })
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
            stopped = self._stop_report(
                mission, mission_control, results=results, action_id=action.action_id
            )
            if stopped is not None:
                return stopped
            # Re-read stored approval just before starting this action so persisted revocation
            # is respected instead of trusting the plan's possibly stale approval object.
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
            if self._store is not None and approval is not None:
                try:
                    self._store.consume_approval(
                        approval.approval_id,
                        mission_id=mission.mission_id,
                        action_fingerprint=fingerprint,
                        signature=approval.signature,
                    )
                except StoreError:
                    mission.record("mission.approval_consumption_failed", {
                        "action_id": action.action_id,
                        "approval_id": approval.approval_id,
                        "error_type": "StoreError",
                    })
                    mission.transition(
                        MissionState.BLOCKED,
                        "The approval could not be consumed atomically; no tool was invoked.",
                    )
                    self._checkpoint(mission)
                    return MissionRunReport(
                        mission_id=mission.mission_id,
                        state=mission.state,
                        completed=False,
                        tool_results=tuple(result for _, result in results),
                        denied_action_ids=(action.action_id,),
                        failed_action_id=action.action_id,
                        reason="Approval was no longer active or could not be consumed exactly once; action was not invoked.",
                    )
            if self._store is not None:
                self._store.record_action_event(
                    mission.mission_id, action.action_id, action.tool_name, fingerprint, "prepared"
                )
                # Do not leave a journal entry stranded at "prepared" because a cancellation
                # landed between two writes. Mark started and let the gateway's preflight check
                # turn a pre-handler cancellation into an explicit unknown outcome.
                self._store.record_action_event(
                    mission.mission_id, action.action_id, action.tool_name, fingerprint, "started"
                )
            try:
                result = self._gateway.invoke(
                    mission,
                    action.tool_name,
                    action.arguments_copy(),
                    approval=approval,
                    execution_control=mission_control,
                )
            except ExecutionCancelled as exc:
                self._journal_unknown(mission, action, fingerprint, type(exc).__name__)
                return self._terminal_report(
                    mission,
                    MissionState.CANCELLED,
                    "Mission was cancelled during a tool action; its external effect may be uncertain.",
                    results=results,
                    action_id=action.action_id,
                )
            except ExecutionDeadlineExceeded as exc:
                self._journal_unknown(mission, action, fingerprint, type(exc).__name__)
                return self._terminal_report(
                    mission,
                    MissionState.FAILED,
                    "Execution deadline expired during a tool action; its external effect may be uncertain.",
                    results=results,
                    action_id=action.action_id,
                )
            except MissionError as exc:
                self._journal_unknown(mission, action, fingerprint, type(exc).__name__)
                return self._terminal_report(
                    mission,
                    MissionState.FAILED,
                    "A planned tool action failed or lost authorization; its external effect may be uncertain.",
                    results=results,
                    action_id=action.action_id,
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

        stopped = self._stop_report(mission, mission_control, results=results)
        if stopped is not None:
            return stopped
        mission.transition(MissionState.VERIFYING, "All planned tool calls returned results.")
        self._checkpoint(mission)
        for action, result in results:
            stopped = self._stop_report(
                mission, mission_control, results=results, action_id=action.action_id
            )
            if stopped is not None:
                return stopped
            try:
                outcome, summary = verifier(action, result)
                mission_control.raise_if_stopped()
                if not isinstance(outcome, EvidenceOutcome) or not isinstance(summary, str) or not summary.strip():
                    raise ValueError("Verifier result must contain an outcome and a non-empty summary.")
            except (ExecutionCancelled, ExecutionDeadlineExceeded) as exc:
                mission.add_evidence(Evidence(
                    criterion=action.criterion,
                    outcome=EvidenceOutcome.INCONCLUSIVE,
                    source_action_id=action.action_id,
                    summary=f"Verification interrupted ({type(exc).__name__}).",
                    observed_at=_now(),
                ))
                self._checkpoint(mission)
                target = MissionState.CANCELLED if isinstance(exc, ExecutionCancelled) else MissionState.FAILED
                return self._terminal_report(
                    mission,
                    target,
                    "Verification was interrupted by cancellation or deadline expiry.",
                    results=results,
                    action_id=action.action_id,
                )
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

        stopped = self._stop_report(mission, mission_control, results=results)
        if stopped is not None:
            return stopped
        completed = verify_mission(mission)
        self._checkpoint(mission)
        return MissionRunReport(
            mission_id=mission.mission_id,
            state=mission.state,
            completed=completed,
            tool_results=tuple(result for _, result in results),
            reason="Mission verified." if completed else "Verification did not pass every required criterion.",
        )
