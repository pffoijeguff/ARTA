from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from arta.core import (
    Approval,
    ApprovalStatus,
    AuthorityKernel,
    Evidence,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    PolicyEffect,
    ToolGateway,
    ToolSpec,
    create_approval_record,
    fingerprint_action,
    verify_mission,
)


NOW = "2026-10-18T08:00:00+00:00"
ISSUED = "2026-10-18T07:00:00+00:00"
EXPIRES = "2026-10-18T09:00:00+00:00"


def mission(*criteria: str) -> Mission:
    item = Mission("Check the requested outcome", criteria or ("report-created",))
    item.transition(MissionState.PLANNED)
    item.transition(MissionState.RUNNING)
    return item


def evidence(
    criterion: str,
    *,
    outcome: EvidenceOutcome = EvidenceOutcome.PASS,
    evidence_id: str = "evidence-1",
    at: str = "2026-10-18T07:30:00+00:00",
) -> Evidence:
    return Evidence(
        criterion=criterion,
        outcome=outcome,
        source_action_id="action-1",
        summary="A synthetic test observation.",
        observed_at=at,
        evidence_id=evidence_id,
    )


def verification_ready(item: Mission) -> Mission:
    item.transition(MissionState.VERIFYING)
    return item


def write_tool() -> ToolSpec:
    return ToolSpec(
        "workspace.write",
        lambda args: {"written": args["path"]},
        read_only=False,
        allowed_arguments=("path", "content"),
        required_arguments=("path", "content"),
        target_argument="path",
        allowed_targets=("reports/final.md", "reports/draft.md"),
    )


def valid_approval(tool: ToolSpec, args: dict[str, object]) -> Approval:
    return create_approval_record(
        tool.name,
        args,
        approver_id="authenticated-test-user",
        approved_at=ISSUED,
        expires_at=EXPIRES,
        approval_id="approval-1",
    )


def test_mission_requires_goal_and_at_least_one_criterion() -> None:
    with pytest.raises(MissionError):
        Mission(" ", ("criterion",))
    with pytest.raises(MissionError):
        Mission("goal", ())
    with pytest.raises(MissionError, match="unique"):
        Mission("goal", ("same", "same"))


def test_state_machine_rejects_skips_without_mutating_state() -> None:
    item = Mission("goal", ("criterion",))
    with pytest.raises(MissionError, match="Invalid mission transition"):
        item.transition(MissionState.COMPLETED)
    assert item.state is MissionState.CREATED
    assert not any(event.event_type == "mission.state_changed" for event in item.audit)


def test_terminal_states_reject_all_followup_transitions() -> None:
    item = verification_ready(mission("report-created"))
    item.add_evidence(evidence("report-created"))
    assert verify_mission(item)
    with pytest.raises(MissionError):
        item.transition(MissionState.FAILED)
    with pytest.raises(MissionError):
        item.add_evidence(evidence("report-created", evidence_id="evidence-2"))


def test_evidence_must_be_structured_and_added_during_execution_or_verification() -> None:
    item = Mission("goal", ("report-created",))
    with pytest.raises(MissionError, match="running or verifying"):
        item.add_evidence(evidence("report-created"))
    item.transition(MissionState.PLANNED)
    item.transition(MissionState.RUNNING)
    with pytest.raises(MissionError, match="structured Evidence"):
        item.add_evidence("report-created")  # type: ignore[arg-type]


def test_unknown_criterion_and_duplicate_evidence_are_rejected() -> None:
    item = mission("report-created")
    with pytest.raises(MissionError, match="unknown"):
        item.add_evidence(evidence("other-criterion"))
    item.add_evidence(evidence("report-created"))
    with pytest.raises(MissionError, match="unique"):
        item.add_evidence(evidence("report-created"))


def test_verification_requires_explicit_passing_evidence_for_every_criterion() -> None:
    item = mission("report-created", "report-hash-checked")
    item.add_evidence(evidence("report-created"))
    verification_ready(item)
    assert not verify_mission(item)
    assert item.state is MissionState.FAILED
    assert item.audit[-2].event_type == "mission.verification_failed"


def test_latest_failed_evidence_overrides_an_earlier_pass() -> None:
    item = mission("report-created")
    item.add_evidence(evidence("report-created", at="2026-10-18T07:30:00+00:00"))
    item.add_evidence(evidence(
        "report-created",
        outcome=EvidenceOutcome.FAIL,
        evidence_id="evidence-2",
        at="2026-10-18T07:45:00+00:00",
    ))
    verification_ready(item)
    assert not verify_mission(item)
    assert item.state is MissionState.FAILED


def test_latest_inconclusive_evidence_blocks_success() -> None:
    item = mission("report-created")
    item.add_evidence(evidence("report-created"))
    item.add_evidence(evidence(
        "report-created",
        outcome=EvidenceOutcome.INCONCLUSIVE,
        evidence_id="evidence-2",
        at="2026-10-18T07:45:00+00:00",
    ))
    verification_ready(item)
    assert not verify_mission(item)


def test_conflicting_evidence_at_same_time_fails_closed() -> None:
    item = mission("report-created")
    timestamp = "2026-10-18T07:45:00+00:00"
    item.add_evidence(evidence("report-created", at=timestamp))
    item.add_evidence(evidence(
        "report-created", outcome=EvidenceOutcome.FAIL,
        evidence_id="evidence-2", at=timestamp,
    ))
    verification_ready(item)
    assert not verify_mission(item)


def test_explicit_latest_pass_for_all_criteria_completes_mission() -> None:
    item = mission("report-created", "report-hash-checked")
    item.add_evidence(evidence("report-created"))
    item.add_evidence(evidence("report-hash-checked", evidence_id="evidence-2"))
    verification_ready(item)
    assert verify_mission(item)
    assert item.state is MissionState.COMPLETED
    assert any(event.event_type == "mission.verification_passed" for event in item.audit)


def test_invalid_or_naive_evidence_timestamp_is_rejected() -> None:
    item = mission("report-created")
    bad = evidence("report-created", at="2026-10-18T07:30:00")
    with pytest.raises(MissionError, match="timezone-aware"):
        item.add_evidence(bad)


def test_unknown_tool_and_unregistered_name_fail_closed() -> None:
    assert AuthorityKernel(clock=lambda: NOW).decide(None).effect is PolicyEffect.DENY
    item = mission("report-created")
    with pytest.raises(MissionError, match="denied"):
        ToolGateway(AuthorityKernel(clock=lambda: NOW)).invoke(item, "not-registered")


def test_read_only_tool_requires_registration_and_exact_argument_contract() -> None:
    item = mission("report-created")
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec(
        "report.read",
        lambda args: {"found": True},
        allowed_arguments=("path",),
        required_arguments=("path",),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    ))
    result = gateway.invoke(item, "report.read", {"path": "reports/final.md"})
    assert result.success and result.output == {"found": True}
    with pytest.raises(MissionError, match="denied"):
        gateway.invoke(item, "report.read", {"path": "reports/secrets.txt"})
    with pytest.raises(MissionError, match="denied"):
        gateway.invoke(item, "report.read", {"path": "reports/final.md", "extra": True})


def test_write_action_requires_action_bound_approval() -> None:
    item = mission("report-created")
    tool = write_tool()
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(tool)
    args = {"path": "reports/final.md", "content": "verified"}
    with pytest.raises(MissionError, match="approval"):
        gateway.invoke(item, tool.name, args)
    approval = valid_approval(tool, args)
    result = gateway.invoke(item, tool.name, args, approval=approval)
    assert result.success
    assert result.output == {"written": "reports/final.md"}


def test_approval_cannot_be_reused_after_arguments_change() -> None:
    tool = write_tool()
    args = {"path": "reports/final.md", "content": "verified"}
    approval = valid_approval(tool, args)
    result = AuthorityKernel(clock=lambda: NOW).decide(
        tool, arguments={**args, "content": "different"}, approval=approval
    )
    assert result.effect is PolicyEffect.DENY
    assert result.reason == "Approval does not match the requested action."


def test_approval_cannot_authorize_a_different_tool_or_target() -> None:
    tool = write_tool()
    args = {"path": "reports/final.md", "content": "verified"}
    approval = valid_approval(tool, args)
    altered_tool = ToolSpec(
        "workspace.publish",
        lambda payload: {"published": True},
        read_only=False,
        allowed_arguments=("path", "content"),
        required_arguments=("path", "content"),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    )
    assert AuthorityKernel(clock=lambda: NOW).decide(
        altered_tool, arguments=args, approval=approval
    ).effect is PolicyEffect.DENY
    assert AuthorityKernel(clock=lambda: NOW).decide(
        tool,
        arguments={"path": "reports/draft.md", "content": "verified"},
        approval=approval,
        
    ).effect is PolicyEffect.DENY


def test_expired_future_denied_and_revoked_approvals_do_not_authorize() -> None:
    tool = write_tool()
    args = {"path": "reports/final.md", "content": "verified"}
    approval = valid_approval(tool, args)
    kernel = AuthorityKernel(clock=lambda: NOW)
    expired = Approval(**{**approval.__dict__, "expires_at": "2026-10-18T08:00:00+00:00"})
    future = Approval(**{**approval.__dict__, "approved_at": "2026-10-18T08:01:00+00:00"})
    revoked = Approval(**{**approval.__dict__, "status": ApprovalStatus.REVOKED})
    assert kernel.decide(tool, arguments=args, approval=expired).effect is PolicyEffect.DENY
    assert kernel.decide(tool, arguments=args, approval=future).effect is PolicyEffect.DENY
    assert kernel.decide(tool, arguments=args, approval=revoked).effect is PolicyEffect.DENY


def test_invalid_arguments_non_finite_values_and_circular_data_are_denied() -> None:
    tool = ToolSpec("report.read", lambda args: {"ok": True}, allowed_arguments=("value",))
    kernel = AuthorityKernel(clock=lambda: NOW)
    assert kernel.decide(tool, arguments={"value": float("nan")}).effect is PolicyEffect.DENY
    circular: dict[str, object] = {}
    circular["self"] = circular
    assert kernel.decide(tool, arguments=circular).effect is PolicyEffect.DENY
    assert kernel.decide(tool, arguments=["not", "an", "object"]).effect is PolicyEffect.DENY  # type: ignore[arg-type]


def test_action_fingerprint_is_stable_across_key_order_but_changes_with_values() -> None:
    first = fingerprint_action("report.write", {"path": "a", "options": {"limit": 5, "format": "text"}})
    second = fingerprint_action("report.write", {"options": {"format": "text", "limit": 5}, "path": "a"})
    changed = fingerprint_action("report.write", {"options": {"format": "text", "limit": 6}, "path": "a"})
    assert first == second
    assert first != changed


def test_tool_failure_audit_does_not_leak_exception_message() -> None:
    item = mission("report-created")
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("broken", lambda args: (_ for _ in ()).throw(RuntimeError("secret material"))))
    with pytest.raises(MissionError) as error:
        gateway.invoke(item, "broken")
    assert "secret material" not in str(error.value)
    assert item.audit[-1].details["success"] is False
    assert item.audit[-1].details["error_type"] == "RuntimeError"


def test_non_json_tool_result_is_rejected_and_audited() -> None:
    item = mission("report-created")
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("bad-output", lambda args: {"bad": object()}))
    with pytest.raises(MissionError, match="failed"):
        gateway.invoke(item, "bad-output")
    assert item.audit[-1].event_type == "tool.invoked"
    assert item.audit[-1].details["success"] is False


def test_tool_is_not_executed_for_a_non_active_mission() -> None:
    item = Mission("goal", ("criterion",))
    calls: list[int] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("counter", lambda args: calls.append(1) or {"ok": True}))
    with pytest.raises(MissionError, match="active mission"):
        gateway.invoke(item, "counter")
    assert calls == []



def test_tool_spec_requires_exactly_one_handler() -> None:
    with pytest.raises(MissionError, match="Exactly one"):
        ToolSpec("missing-handler")
    with pytest.raises(MissionError, match="Exactly one"):
        ToolSpec(
            "two-handlers",
            lambda args: {"ok": True},
            contextual_handler=lambda args, control: {"ok": True},
        )
