from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arta.approvals import HmacApprovalAuthority
from arta.core import AuthorityKernel, Mission, MissionError, MissionState, ToolGateway
from arta.sandbox import BubblewrapSandbox, SandboxResult
from arta.sandbox_tool import register_sandbox_tool


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Bubblewrap adapter is Linux-only.")
KEY = b"test-only-sandbox-tool-authority-key"


def make_sandbox(tmp_path: Path, monkeypatch, result: SandboxResult | None = None):
    workspace = tmp_path / "project"
    workspace.mkdir()
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_bwrap.chmod(0o755)
    sandbox = BubblewrapSandbox(
        workspace,
        allowed_executables={"python": "/usr/bin/true", "true": "/usr/bin/true"},
        bwrap_path=fake_bwrap,
    )
    calls = []

    def fake_run(executable, arguments=(), *, timeout_seconds=None):
        calls.append((executable, tuple(arguments), timeout_seconds))
        return result or SandboxResult(
            executable=executable,
            return_code=0,
            stdout="ok",
            stderr="",
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
            elapsed_seconds=0.01,
        )

    monkeypatch.setattr(sandbox, "run", fake_run)
    return sandbox, calls


def active_mission() -> Mission:
    mission = Mission("Run a reviewed command", ("exit-code-is-zero",))
    mission.transition(MissionState.PLANNED)
    mission.transition(MissionState.RUNNING)
    return mission


def signed_approval(authority, tool_name, arguments):
    now = datetime.now(timezone.utc)
    return authority.issue(
        tool_name,
        arguments,
        approver_id="trusted-test-operator",
        approved_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=2)).isoformat(),
    )


def test_registered_sandbox_tool_requires_approval_and_calls_only_the_adapter(tmp_path, monkeypatch) -> None:
    sandbox, calls = make_sandbox(tmp_path, monkeypatch)
    authority = HmacApprovalAuthority(KEY)
    gateway = ToolGateway(AuthorityKernel(approval_verifier=authority.verify))
    spec = register_sandbox_tool(gateway, sandbox)
    mission = active_mission()
    arguments = {"executable": "python", "arguments": ["-I", "-c", "print('ok')"]}

    with pytest.raises(MissionError, match="requires approval"):
        gateway.invoke(mission, spec.name, arguments)
    assert calls == []
    assert mission.state is MissionState.AWAITING_APPROVAL

    approval = signed_approval(authority, spec.name, arguments)
    result = gateway.invoke(mission, spec.name, arguments, approval=approval)
    assert result.success
    assert result.output["success"] is True
    assert calls == [("python", ("-I", "-c", "print('ok')"), None)]


def test_registered_sandbox_tool_rejects_unknown_alias_before_process_launch(tmp_path, monkeypatch) -> None:
    sandbox, calls = make_sandbox(tmp_path, monkeypatch)
    gateway = ToolGateway()
    spec = register_sandbox_tool(gateway, sandbox)
    mission = active_mission()
    with pytest.raises(MissionError, match="denied"):
        gateway.invoke(mission, spec.name, {"executable": "/bin/sh", "arguments": ["-c", "id"]})
    assert calls == []


def test_registered_sandbox_tool_rejects_non_json_argv_and_invalid_timeout(tmp_path, monkeypatch) -> None:
    sandbox, calls = make_sandbox(tmp_path, monkeypatch)
    authority = HmacApprovalAuthority(KEY)
    gateway = ToolGateway(AuthorityKernel(approval_verifier=authority.verify))
    spec = register_sandbox_tool(gateway, sandbox)
    mission = active_mission()
    arguments = {"executable": "python", "arguments": "print('no')"}
    with pytest.raises(MissionError, match="requires approval"):
        gateway.invoke(mission, spec.name, arguments)
    with pytest.raises(MissionError, match="failed"):
        gateway.invoke(mission, spec.name, arguments, approval=signed_approval(authority, spec.name, arguments))
    assert calls == []
