"""Explicit bridge from the OS-isolated runner into ToolGateway.

Registering this adapter is opt-in. It marks process execution as a side effect and
requires an action-bound approval; it never executes commands through the host shell.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .core import MissionError, ToolGateway, ToolSpec
from .sandbox import BubblewrapSandbox, SandboxError


def register_sandbox_tool(
    gateway: ToolGateway,
    sandbox: BubblewrapSandbox,
    *,
    tool_name: str = "sandbox.run",
) -> ToolSpec:
    """Register a bounded, approval-gated command tool backed by BubblewrapSandbox.

    The executable alias is policy-targeted to the runtime's fixed alias allowlist.
    The command argument vector is data, not a shell command. Workspace writes inside
    the sandbox are ephemeral; this tool deliberately has no implicit write-back path.
    """
    if not isinstance(gateway, ToolGateway):
        raise MissionError("A ToolGateway instance is required.")
    if not isinstance(sandbox, BubblewrapSandbox):
        raise MissionError("A trusted BubblewrapSandbox instance is required.")
    if not isinstance(tool_name, str) or not tool_name or tool_name != tool_name.strip():
        raise MissionError("Tool name must be a non-empty trimmed string.")
    aliases = sandbox.allowed_aliases
    if not aliases:
        raise MissionError("The sandbox executable allowlist is empty.")

    def run_sandbox(arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        executable = arguments.get("executable")
        argv = arguments.get("arguments", [])
        timeout = arguments.get("timeout_seconds")
        if not isinstance(executable, str) or executable not in aliases:
            raise SandboxError("Executable alias is not on the trusted runtime allowlist.")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise SandboxError("arguments must be a JSON array of strings.")
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float))
        ):
            raise SandboxError("timeout_seconds must be a finite number.")
        result = sandbox.run(executable, tuple(argv), timeout_seconds=timeout)
        return {
            "executable": result.executable,
            "return_code": result.return_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "elapsed_seconds": result.elapsed_seconds,
            "success": result.return_code == 0 and not result.timed_out,
        }

    spec = ToolSpec(
        name=tool_name,
        handler=run_sandbox,
        read_only=False,
        requires_approval=True,
        allowed_arguments=("executable", "arguments", "timeout_seconds"),
        required_arguments=("executable",),
        target_argument="executable",
        allowed_targets=aliases,
        timeout_seconds=65.0,
    )
    gateway.register(spec)
    return spec
