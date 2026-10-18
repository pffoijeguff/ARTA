"""Composition root for JWT-authenticated, approval-gated sandbox execution."""
from __future__ import annotations
from collections.abc import Mapping, Sequence
from typing import Any
from .approvals import HmacApprovalAuthority
from .control import CancellationToken
from .core import Approval, AuthorityKernel, Mission, MissionError, ToolGateway
from .identity import JwtPrincipalAuthenticator, TrustedApprovalService
from .persistence import SQLiteMissionStore
from .runner import ActionVerifier, MissionPlan, MissionRunReport, MissionRunner
from .sandbox import BubblewrapSandbox
from .sandbox_tool import register_sandbox_tool

class SecureRuntime:
    """Wire trusted identity, durable approvals, policy, sandbox execution, and evidence.

    Token issuance/key rotation remain the responsibility of a trusted identity provider.
    This runtime has one command tool and refuses plans that contain any other tool.
    """
    def __init__(self, *, authenticator: JwtPrincipalAuthenticator,
                 approval_authority: HmacApprovalAuthority, store: SQLiteMissionStore,
                 sandbox: BubblewrapSandbox,
                 required_scopes_by_tool: Mapping[str, Sequence[str]],
                 tool_name: str = "sandbox.run",
                 max_approval_lifetime_seconds: int = 300) -> None:
        if not isinstance(authenticator, JwtPrincipalAuthenticator):
            raise MissionError("SecureRuntime requires a configured JWT authenticator.")
        if not isinstance(approval_authority, HmacApprovalAuthority):
            raise MissionError("SecureRuntime requires a trusted HMAC approval authority.")
        if not isinstance(store, SQLiteMissionStore):
            raise MissionError("SecureRuntime requires a durable SQLiteMissionStore.")
        if not isinstance(sandbox, BubblewrapSandbox):
            raise MissionError("SecureRuntime requires BubblewrapSandbox; direct fallback is forbidden.")
        if not isinstance(tool_name, str) or not tool_name or tool_name != tool_name.strip():
            raise MissionError("SecureRuntime tool name must be non-empty and trimmed.")
        if not isinstance(required_scopes_by_tool, Mapping) or tool_name not in required_scopes_by_tool:
            raise MissionError("Explicit approval scopes must be configured for the sandbox tool.")
        raw_scopes = required_scopes_by_tool[tool_name]
        if isinstance(raw_scopes, (str, bytes)) or not isinstance(raw_scopes, Sequence):
            raise MissionError("Sandbox approval scopes must be a sequence, not a string.")
        scopes = tuple(raw_scopes)
        if any(not isinstance(scope, str) or not scope or scope != scope.strip() for scope in scopes):
            raise MissionError("Sandbox approval scopes must be non-empty trimmed strings.")
        if len(set(scopes)) != len(scopes):
            raise MissionError("Sandbox approval scopes must be unique.")
        self._tool_name = tool_name
        self._gateway = ToolGateway(AuthorityKernel(approval_verifier=approval_authority.verify))
        register_sandbox_tool(self._gateway, sandbox, tool_name=tool_name)
        self._approvals = TrustedApprovalService(
            authenticator=authenticator, authority=approval_authority, store=store,
            required_scopes_by_tool={tool_name: scopes},
            max_approval_lifetime_seconds=max_approval_lifetime_seconds)
        self._runner = MissionRunner(self._gateway, store)

    @property
    def tool_name(self) -> str:
        return self._tool_name

    def issue_approval(self, bearer_token: str, arguments: Mapping[str, Any], *,
                       lifetime_seconds: int = 120) -> Approval:
        """Authenticate the bearer token and persist approval for these exact arguments."""
        return self._approvals.issue_approval(
            bearer_token, self._tool_name, arguments, lifetime_seconds=lifetime_seconds)

    def run(self, mission: Mission, plan: MissionPlan, verifier: ActionVerifier, *,
            cancellation_token: CancellationToken | None = None,
            timeout_seconds: float | None = None) -> MissionRunReport:
        """Execute a mission only when every planned action uses this sandbox tool."""
        if not isinstance(plan, MissionPlan):
            raise MissionError("SecureRuntime requires a validated MissionPlan.")
        if any(action.tool_name != self._tool_name for action in plan.actions):
            raise MissionError("SecureRuntime refuses plans containing tools outside its sandbox boundary.")
        return self._runner.run(mission, plan, verifier,
                                cancellation_token=cancellation_token,
                                timeout_seconds=timeout_seconds)
