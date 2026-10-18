from __future__ import annotations

from arta.core import (
    Approval,
    AuthorityKernel,
    EvidenceOutcome,
    Mission,
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
