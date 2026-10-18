from __future__ import annotations

import threading
import time

import pytest

from arta.control import CancellationToken, ExecutionControl
from arta.persistence import SQLiteMissionStore
from arta.core import (
    MAX_TOOL_INVOCATIONS_PER_MISSION,
    Approval,
    AuthorityKernel,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    ToolGateway,
    ToolSpec,
    create_approval_record,
)
from arta.runner import MissionPlan, MissionRunner, PlannedAction


NOW = "2026-10-18T08:00:00+00:00"
ISSUED = "2026-10-18T07:00:00+00:00"
EXPIRES = "2026-10-18T09:00:00+00:00"


def passing_verifier(action: PlannedAction, result):
    return EvidenceOutcome.PASS, f"Independent fixture check passed for {action.action_id}."


def test_mission_plan_rejects_more_actions_than_the_execution_budget() -> None:
    actions = tuple(
        PlannedAction(f"action-{index}", "report.read", "report-read")
        for index in range(MAX_TOOL_INVOCATIONS_PER_MISSION + 1)
    )
    with pytest.raises(MissionError, match="at most"):
        MissionPlan(actions)


def test_runner_executes_and_verifies_a_read_only_mission_end_to_end() -> None:
    mission = Mission("Read and validate a report", ("report-read",))
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec(
        "report.read",
        lambda args: calls.append(args["path"]) or {"content": "fixture", "found": True},
        allowed_arguments=("path",),
        required_arguments=("path",),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    ))
    plan = MissionPlan((
        PlannedAction("read-1", "report.read", "report-read", {"path": "reports/final.md"}),
    ))

    report = MissionRunner(gateway).run(mission, plan, passing_verifier)

    assert report.completed
    assert report.state is MissionState.COMPLETED
    assert calls == ["reports/final.md"]
    assert len(report.tool_results) == 1
    assert mission.evidence[0].source_action_id == "read-1"
    assert mission.evidence[0].outcome is EvidenceOutcome.PASS
    assert any(event.event_type == "mission.verification_passed" for event in mission.audit)


def test_runner_preflights_every_action_and_executes_nothing_until_approval_exists() -> None:
    mission = Mission("Read and update a report", ("report-read", "report-written"))
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec(
        "report.read",
        lambda args: calls.append("read") or {"read": True},
        allowed_arguments=("path",),
        required_arguments=("path",),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    ))
    write_tool = ToolSpec(
        "report.write",
        lambda args: calls.append("write") or {"written": args["path"]},
        read_only=False,
        allowed_arguments=("path", "content"),
        required_arguments=("path", "content"),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    )
    gateway.register(write_tool)
    read = PlannedAction("read-1", "report.read", "report-read", {"path": "reports/final.md"})
    write_args = {"path": "reports/final.md", "content": "reviewed"}
    unapproved = PlannedAction("write-1", "report.write", "report-written", write_args)
    runner = MissionRunner(gateway)

    pending = runner.run(mission, MissionPlan((read, unapproved)), passing_verifier)

    assert pending.state is MissionState.AWAITING_APPROVAL
    assert pending.pending_action_ids == ("write-1",)
    assert calls == []
    assert not pending.tool_results
    request_events = [
        event for event in mission.audit if event.event_type == "tool.approval_requested"
    ]
    assert len(request_events) == 1
    assert request_events[0].details["action_id"] == "write-1"
    assert request_events[0].details["tool"] == "report.write"
    assert request_events[0].details["action_fingerprint"]

    approval = create_approval_record(
        write_tool.name,
        write_args,
        approver_id="authenticated-test-user",
        approved_at=ISSUED,
        expires_at=EXPIRES,
        approval_id="write-approval",
    )
    approved_write = PlannedAction(
        "write-1", "report.write", "report-written", write_args, approval=approval
    )
    completed = runner.run(mission, MissionPlan((read, approved_write)), passing_verifier)

    assert completed.completed
    assert completed.state is MissionState.COMPLETED
    assert calls == ["read", "write"]
    consumed = [
        event for event in mission.audit if event.event_type == "tool.approval_consumed"
    ]
    assert len(consumed) == 1
    assert consumed[0].details["approval_id"] == "write-approval"


def test_denied_action_blocks_whole_plan_before_any_tool_runs() -> None:
    mission = Mission("Run only permitted actions", ("allowed", "forbidden"))
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("safe.read", lambda args: calls.append("safe") or {"ok": True}))
    plan = MissionPlan((
        PlannedAction("safe-1", "safe.read", "allowed"),
        PlannedAction("unknown-1", "unregistered.tool", "forbidden"),
    ))

    report = MissionRunner(gateway).run(mission, plan, passing_verifier)

    assert report.state is MissionState.BLOCKED
    assert report.denied_action_ids == ("unknown-1",)
    assert calls == []
    assert not report.tool_results


def test_plan_must_cover_each_acceptance_criterion() -> None:
    mission = Mission("Read two artifacts", ("artifact-a", "artifact-b"))
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("safe.read", lambda args: calls.append("ran") or {"ok": True}))
    plan = MissionPlan((PlannedAction("read-a", "safe.read", "artifact-a"),))

    report = MissionRunner(gateway).run(mission, plan, passing_verifier)

    assert report.state is MissionState.BLOCKED
    assert calls == []
    assert "cover" in report.reason


def test_verifier_failure_makes_final_mission_fail() -> None:
    mission = Mission("Check an artifact", ("artifact-valid",))
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("artifact.read", lambda args: {"content": "fixture"}))
    plan = MissionPlan((PlannedAction("read-1", "artifact.read", "artifact-valid"),))

    report = MissionRunner(gateway).run(
        mission,
        plan,
        lambda action, result: (EvidenceOutcome.FAIL, "Fixture integrity check failed."),
        
    )

    assert not report.completed
    assert report.state is MissionState.FAILED
    assert mission.evidence[0].outcome is EvidenceOutcome.FAIL


def test_verifier_exception_fails_closed_as_inconclusive() -> None:
    mission = Mission("Check an artifact", ("artifact-valid",))
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("artifact.read", lambda args: {"content": "fixture"}))
    plan = MissionPlan((PlannedAction("read-1", "artifact.read", "artifact-valid"),))

    def broken_verifier(action, result):
        raise RuntimeError("must not be persisted")

    report = MissionRunner(gateway).run(mission, plan, broken_verifier)

    assert report.state is MissionState.FAILED
    assert mission.evidence[0].outcome is EvidenceOutcome.INCONCLUSIVE
    assert "must not be persisted" not in mission.evidence[0].summary
    assert "RuntimeError" in mission.evidence[0].summary


def test_planned_action_uses_validated_snapshot_not_later_mutated_arguments() -> None:
    mission = Mission("Read the approved path", ("path-read",))
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec(
        "safe.read",
        lambda args: calls.append(args["path"]) or {"ok": True},
        allowed_arguments=("path",),
        required_arguments=("path",),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    ))
    arguments = {"path": "reports/final.md"}
    planned = PlannedAction("read-1", "safe.read", "path-read", arguments)
    arguments["path"] = "reports/other.md"

    report = MissionRunner(gateway).run(mission, MissionPlan((planned,)), passing_verifier)

    assert report.completed
    assert calls == ["reports/final.md"]


def test_runtime_failure_stops_later_actions_and_reports_partial_results() -> None:
    mission = Mission("Run two actions", ("first-action", "second-action"))
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))

    def fail(_args):
        calls.append("first")
        raise RuntimeError("private execution detail")

    gateway.register(ToolSpec("first", fail))
    gateway.register(ToolSpec("second", lambda args: calls.append("second") or {"ok": True}))
    plan = MissionPlan((
        PlannedAction("action-1", "first", "first-action"),
        PlannedAction("action-2", "second", "second-action"),
    ))

    report = MissionRunner(gateway).run(mission, plan, passing_verifier)

    assert report.state is MissionState.FAILED
    assert report.failed_action_id == "action-1"
    assert calls == ["first"]
    assert not report.tool_results
    assert "private execution detail" not in report.reason


def test_duplicate_action_ids_are_rejected_during_plan_construction() -> None:
    first = PlannedAction("same-id", "tool-a", "criterion-a")
    second = PlannedAction("same-id", "tool-b", "criterion-b")
    try:
        MissionPlan((first, second))
    except ValueError as exc:
        assert "unique" in str(exc)
    else:
        raise AssertionError("Duplicate action ids must not be accepted.")



def test_pre_cancelled_mission_does_not_start_any_tool() -> None:
    calls: list[str] = []
    gateway = ToolGateway()
    gateway.register(ToolSpec("safe.read", lambda args: calls.append("ran") or {"ok": True}))
    item = Mission("Do not start a cancelled mission", ("read",))
    plan = MissionPlan((PlannedAction("read-1", "safe.read", "read"),))
    token = CancellationToken()
    assert token.cancel()

    report = MissionRunner(gateway).run(
        item,
        plan,
        passing_verifier,
        cancellation_token=token,
    )

    assert report.state is MissionState.CANCELLED
    assert not report.completed
    assert calls == []


def test_cancellation_during_cooperative_tool_is_journaled_as_uncertain() -> None:
    calls: list[str] = []
    gateway = ToolGateway()
    token = CancellationToken()

    def cooperative(_args, control: ExecutionControl):
        calls.append("started")
        while True:
            control.raise_if_stopped()
            time.sleep(0.002)

    gateway.register(ToolSpec(
        "cooperative.wait",
        contextual_handler=cooperative,
        timeout_seconds=1.0,
    ))
    item = Mission("Cancel a waiting tool", ("waited",))
    plan = MissionPlan((PlannedAction("wait-1", "cooperative.wait", "waited"),))
    with SQLiteMissionStore(":memory:") as store:
        timer = threading.Timer(0.03, token.cancel)
        timer.start()
        try:
            report = MissionRunner(gateway, store).run(
                item, plan, passing_verifier, cancellation_token=token, timeout_seconds=2.0
            )
            assert report.state is MissionState.CANCELLED
            assert not report.completed
            assert calls == ["started"]
            assert store.action_journal(item.mission_id)[0]["status"] == "unknown"
            assert store.unresolved_actions(item.mission_id)[0]["status"] == "unknown"
        finally:
            timer.cancel()
            timer.join(timeout=1.0)


def test_tool_specific_deadline_stops_a_cooperative_handler() -> None:
    calls: list[str] = []
    gateway = ToolGateway()

    def cooperative(_args, control: ExecutionControl):
        calls.append("started")
        while True:
            control.raise_if_stopped()
            time.sleep(0.002)

    gateway.register(ToolSpec(
        "cooperative.wait",
        contextual_handler=cooperative,
        timeout_seconds=0.015,
    ))
    item = Mission("Bound a tool's runtime", ("waited",))
    plan = MissionPlan((PlannedAction("wait-1", "cooperative.wait", "waited"),))

    with SQLiteMissionStore(":memory:") as store:
        report = MissionRunner(gateway, store).run(item, plan, passing_verifier)
        assert report.state is MissionState.FAILED
        assert report.failed_action_id == "wait-1"
        assert calls == ["started"]
        assert store.action_journal(item.mission_id)[0]["status"] == "unknown"
        assert store.unresolved_actions(item.mission_id)[0]["error_type"] == "ExecutionDeadlineExceeded"


def test_non_cooperative_handler_may_finish_effect_after_deadline() -> None:
    effects: list[str] = []

    def ordinary_handler(_args):
        time.sleep(0.02)
        effects.append("effect-finished")
        return {"ok": True}

    gateway = ToolGateway()
    gateway.register(ToolSpec("slow.read", ordinary_handler, timeout_seconds=0.001))
    item = Mission("Demonstrate cooperative-timeout boundary", ("read",))
    plan = MissionPlan((PlannedAction("slow-1", "slow.read", "read"),))

    with SQLiteMissionStore(":memory:") as store:
        report = MissionRunner(gateway, store).run(item, plan, passing_verifier)
        assert report.state is MissionState.FAILED
        assert effects == ["effect-finished"]
        assert "uncertain" in report.reason
        assert store.action_journal(item.mission_id)[0]["status"] == "unknown"


def test_mission_deadline_expires_before_any_tool_starts() -> None:
    calls: list[str] = []
    gateway = ToolGateway()
    gateway.register(ToolSpec("safe.read", lambda args: calls.append("ran") or {"ok": True}))
    item = Mission("Never start after an expired deadline", ("read",))
    plan = MissionPlan((PlannedAction("read-1", "safe.read", "read"),))

    report = MissionRunner(gateway).run(
        item,
        plan,
        passing_verifier,
        timeout_seconds=1e-12,
    )

    assert report.state is MissionState.FAILED
    assert calls == []


def test_cancellation_during_verification_cannot_produce_success() -> None:
    gateway = ToolGateway()
    gateway.register(ToolSpec("safe.read", lambda args: {"ok": True}))
    item = Mission("Do not complete a cancelled verification", ("read",))
    plan = MissionPlan((PlannedAction("read-1", "safe.read", "read"),))
    token = CancellationToken()

    def cancel_then_claim_pass(_action, _result):
        token.cancel()
        return EvidenceOutcome.PASS, "This result must not authorize completion."

    report = MissionRunner(gateway).run(
        item,
        plan,
        cancel_then_claim_pass,
        cancellation_token=token,
    )

    assert report.state is MissionState.CANCELLED
    assert not report.completed
    assert item.evidence[-1].outcome is EvidenceOutcome.INCONCLUSIVE
