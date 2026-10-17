import pytest

from arta.core import (
    AuthorityKernel, Mission, MissionError, MissionState, PolicyEffect,
    ToolGateway, ToolSpec, verify_mission,
)


def active_mission():
    item = Mission("Check sample", ("sample checked",))
    item.transition(MissionState.PLANNED)
    item.transition(MissionState.RUNNING)
    return item


def test_mission_requires_goal_and_acceptance_criteria():
    with pytest.raises(MissionError):
        Mission(" ", ("criterion",))
    with pytest.raises(MissionError):
        Mission("goal", ())


def test_state_machine_rejects_skipping_required_states():
    item = Mission("goal", ("criterion",))
    with pytest.raises(MissionError):
        item.transition(MissionState.COMPLETED)


def test_authority_is_default_deny_for_unknown_tools():
    assert AuthorityKernel().decide(None).effect is PolicyEffect.DENY


def test_tool_gateway_only_runs_registered_tool():
    item = active_mission()
    with pytest.raises(MissionError, match="denied"):
        ToolGateway().invoke(item, "not-registered")


def test_write_like_tool_requires_explicit_approval():
    item = active_mission()
    gateway = ToolGateway()
    gateway.register(ToolSpec("change-setting", lambda args: {"changed": True},
                              read_only=False, requires_approval=True))
    with pytest.raises(MissionError, match="approval"):
        gateway.invoke(item, "change-setting")
    result = gateway.invoke(item, "change-setting", approved=True)
    assert result.success and result.output == {"changed": True}


def test_tool_failure_is_audited_without_leaking_exception_message():
    item = active_mission()
    gateway = ToolGateway()
    def broken(args):
        raise RuntimeError("sensitive detail")
    gateway.register(ToolSpec("broken", broken))
    with pytest.raises(MissionError) as error:
        gateway.invoke(item, "broken")
    assert "sensitive detail" not in str(error.value)
    assert item.audit[-1].details["success"] is False
    assert "error_type" in item.audit[-1].details


def test_verification_requires_evidence_for_each_criterion():
    item = Mission("goal", ("first done", "second done"))
    item.transition(MissionState.PLANNED)
    item.transition(MissionState.RUNNING)
    item.add_evidence("first done")
    item.transition(MissionState.VERIFYING)
    assert not verify_mission(item)
    assert item.state is MissionState.FAILED


def test_matching_evidence_completes_mission_and_leaves_audit_trail():
    item = Mission("goal", ("first done", "second done"))
    item.transition(MissionState.PLANNED)
    item.transition(MissionState.RUNNING)
    item.add_evidence("first done")
    item.add_evidence("second done")
    item.transition(MissionState.VERIFYING)
    assert verify_mission(item)
    assert item.state is MissionState.COMPLETED
    assert any(event.event_type == "mission.verification_passed" for event in item.audit)


def test_evidence_cannot_be_added_before_execution():
    item = Mission("goal", ("criterion",))
    with pytest.raises(MissionError):
        item.add_evidence("criterion")
