from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from arta.sandbox import BubblewrapSandbox, SandboxError


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Bubblewrap is Linux-only.")


def make_sandbox(tmp_path: Path) -> BubblewrapSandbox:
    workspace = tmp_path / "project"
    workspace.mkdir()
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_bwrap.chmod(0o755)
    return BubblewrapSandbox(
        workspace,
        allowed_executables={"true": "/usr/bin/true"},
        bwrap_path=fake_bwrap,
    )


def test_command_construction_uses_required_isolation_and_never_host_shell(tmp_path) -> None:
    sandbox = make_sandbox(tmp_path)
    command = sandbox._build_command(
        "true",
        ("argument with spaces; $(touch /tmp/host-file)",),
        timeout_seconds=2.0,
    )

    assert command[0] == sandbox._bwrap
    assert "--unshare-user" in command
    assert "--unshare-pid" in command
    assert "--unshare-net" in command
    assert "--unshare-ipc" in command
    assert "--unshare-uts" in command
    assert "--disable-userns" in command
    assert "--clearenv" in command
    assert "--ro-bind" in command and "/source" in command
    assert "--tmpfs" in command and "/workspace" in command
    assert "--size" in command
    assert command[-1] == "argument with spaces; $(touch /tmp/host-file)"
    assert "shell" not in command


def test_untrusted_args_are_argv_values_and_probe_runs_before_task(tmp_path, monkeypatch) -> None:
    sandbox = make_sandbox(tmp_path)
    launches: list[tuple[list[str], dict]] = []

    class FakeProcess:
        next_pid = 1000

        def __init__(self, command, **kwargs):
            self.command = list(command)
            self.kwargs = kwargs
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode = None
            self.pid = FakeProcess.next_pid
            FakeProcess.next_pid += 1
            launches.append((self.command, kwargs))

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("arta.sandbox.subprocess.Popen", FakeProcess)
    result = sandbox.run("true", ("quoted ; text",), timeout_seconds=2.0)

    assert result.return_code == 0
    assert not result.timed_out
    assert len(launches) == 2  # isolation preflight, then task
    assert all(opts["shell"] is False for _, opts in launches)
    assert launches[0][0][-1].endswith("test -d /source && test -d /workspace")
    assert launches[1][0][-1] == "quoted ; text"
    assert launches[1][1]["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def test_failed_isolation_probe_fails_closed_without_starting_task(tmp_path, monkeypatch) -> None:
    sandbox = make_sandbox(tmp_path)
    calls = []

    class FakeProcess:
        def __init__(self, command, **kwargs):
            calls.append(list(command))
            self.command = list(command)
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode = None
            self.pid = 1001

        def wait(self, timeout=None):
            self.returncode = 1
            return 1

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("arta.sandbox.subprocess.Popen", FakeProcess)
    with pytest.raises(SandboxError, match="preflight failed"):
        sandbox.run("true")
    assert len(calls) == 1


def test_task_timeout_kills_supervisor_and_returns_timed_out_result(tmp_path, monkeypatch) -> None:
    sandbox = make_sandbox(tmp_path)
    calls = []

    class FakeProcess:
        def __init__(self, command, **kwargs):
            self.command = list(command)
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode = None
            self.pid = 1002
            self.index = len(calls)
            self.killed = False
            calls.append(self)

        def wait(self, timeout=None):
            if self.index == 0:
                self.returncode = 0
                return 0
            if self.killed:
                self.returncode = -9
                return -9
            raise subprocess.TimeoutExpired(self.command, timeout)

        def kill(self):
            self.killed = True
            self.returncode = -9

    monkeypatch.setattr("arta.sandbox.subprocess.Popen", FakeProcess)
    result = sandbox.run("true", timeout_seconds=1.0)
    assert result.timed_out
    assert result.return_code == -9
    assert len(calls) == 2


def test_bad_arguments_and_unknown_executable_alias_are_rejected(tmp_path) -> None:
    sandbox = make_sandbox(tmp_path)
    with pytest.raises(SandboxError, match="allowlist"):
        sandbox.run("/usr/bin/true")
    with pytest.raises(SandboxError, match="NUL"):
        sandbox.run("true", ("bad\x00argument",))
    with pytest.raises(SandboxError, match="not a shell command"):
        sandbox.run("true", "true")


def test_missing_bubblewrap_never_falls_back_to_host_execution(tmp_path) -> None:
    workspace = tmp_path / "project"
    workspace.mkdir()
    with pytest.raises(SandboxError, match="missing or not executable"):
        BubblewrapSandbox(
            workspace,
            allowed_executables={"true": "/usr/bin/true"},
            bwrap_path=tmp_path / "missing-bwrap",
        )


@pytest.mark.skipif(
    os.environ.get("ARTA_RUN_BWRAP_INTEGRATION") != "1" or shutil.which("bwrap") is None,
    reason="Opt-in integration test requires an installed Bubblewrap with usable user namespaces.",
)
def test_real_bubblewrap_blocks_host_writes_and_network(tmp_path) -> None:
    workspace = tmp_path / "project"
    workspace.mkdir()
    (workspace / "input.txt").write_text("fixture", encoding="utf-8")
    marker = Path("/tmp") / f"arta-sandbox-host-marker-{os.getpid()}.txt"
    # Use the OS-managed interpreter under a read-only runtime root. setup-python may
    # prepend /opt/hostedtoolcache to PATH, which is intentionally not mounted in sandbox.
    python = next(
        (candidate for candidate in ("/usr/bin/python3", "/bin/python3")
         if Path(candidate).is_file() and os.access(candidate, os.X_OK)),
        None,
    )
    if not python:
        pytest.fail("No OS-managed python3 exists under /usr or /bin for the real sandbox test.")
    sandbox = BubblewrapSandbox(
        workspace,
        allowed_executables={"python": python},
        default_timeout_seconds=5,
        max_timeout_seconds=10,
        memory_limit_bytes=512 * 1024 * 1024,
        output_limit_bytes=8192,
        workspace_limit_bytes=16 * 1024 * 1024,
        temp_limit_bytes=4 * 1024 * 1024,
    )
    code = (
        "from pathlib import Path; import socket; "
        f"Path({str(marker)!r}).write_text('sandbox-only'); "
        "s=socket.socket(); "
        "result=s.connect_ex(('1.1.1.1', 443)); "
        "print('network_blocked' if result != 0 else 'network_available'); s.close()"
    )
    result = sandbox.run("python", ("-I", "-c", code), timeout_seconds=5)
    assert result.return_code == 0, result.stderr
    assert "network_blocked" in result.stdout
    assert not marker.exists()
    assert (workspace / "input.txt").read_text(encoding="utf-8") == "fixture"
