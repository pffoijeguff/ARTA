"""ARTA mission kernel vertical slice."""
from .approvals import HmacApprovalAuthority
from .core import (
    Approval,
    ApprovalStatus,
    AuthorityKernel,
    AuditEvent,
    Evidence,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    PolicyDecision,
    PolicyEffect,
    ToolGateway,
    ToolResult,
    ToolSpec,
    create_approval_record,
    fingerprint_action,
    verify_mission,
)
from .control import CancellationToken, ExecutionCancelled, ExecutionControl, ExecutionDeadlineExceeded
from .runner import MissionPlan, MissionRunReport, MissionRunner, PlannedAction
from .persistence import SQLiteMissionStore, StoreError, StoreIntegrityError
from .workspace import WorkspaceAdapter, WorkspaceError
from .identity import AuthenticatedPrincipal, IdentityError, JwtPrincipalAuthenticator, PrincipalAuthenticator, TrustedApprovalService
from .oidc import OidcJwksAuthenticator
from .oidc_login import LoginStart, OidcAuthorizationCodeClient, OidcLoginResult
from .sandbox import BubblewrapSandbox, SandboxError, SandboxResult
from .sandbox_tool import register_sandbox_tool
from .runtime import SecureRuntime

__all__ = [
    "HmacApprovalAuthority",
    "Approval",
    "CancellationToken",
    "ExecutionCancelled",
    "ExecutionControl",
    "ExecutionDeadlineExceeded",
    "ApprovalStatus",
    "AuthorityKernel",
    "AuditEvent",
    "Evidence",
    "EvidenceOutcome",
    "Mission",
    "MissionError",
    "MissionState",
    "SQLiteMissionStore",
    "StoreError",
    "StoreIntegrityError",
    "PolicyDecision",
    "PolicyEffect",
    "ToolGateway",
    "ToolResult",
    "ToolSpec",
    "WorkspaceAdapter",
    "WorkspaceError",
    "AuthenticatedPrincipal",
    "IdentityError",
    "JwtPrincipalAuthenticator",
    "PrincipalAuthenticator",
    "OidcJwksAuthenticator",
    "LoginStart",
    "OidcAuthorizationCodeClient",
    "OidcLoginResult",
    "TrustedApprovalService",
    "BubblewrapSandbox",
    "SandboxError",
    "SandboxResult",
    "register_sandbox_tool",
    "SecureRuntime",
    "create_approval_record",
    "fingerprint_action",
    "verify_mission",
]
