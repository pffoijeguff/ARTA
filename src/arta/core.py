"""Minimal, auditable ARTA mission kernel.

This first vertical slice is intentionally in-memory and does not execute host commands,
access the filesystem, or connect to external services.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class MissionState(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


TRANSITIONS = {
    MissionState.CREATED: {MissionState.PLANNED, MissionState.BLOCKED},
    MissionState.PLANNED: {MissionState.AWAITING_APPROVAL, MissionState.RUNNING, MissionState.BLOCKED},
    MissionState.AWAITING_APPROVAL: {MissionState.RUNNING, MissionState.BLOCKED},
    MissionState.RUNNING: {MissionState.VERIFYING, MissionState.FAILED, MissionState.BLOCKED},
    MissionState.VERIFYING: {MissionState.COMPLETED, MissionState.FAILED, MissionState.BLOCKED},
    MissionState.COMPLETED: set(),
    MissionState.BLOCKED: set(),
    MissionState.FAILED: set(),
}


class MissionError(ValueError):
    """Raised when a mission operation violates its contract."""


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    mission_id: str
    timestamp: str = field(default_factory=_now)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Mission:
    goal: str
    acceptance_criteria: tuple[str, ...]
    mission_id: str = field(default_factory=lambda: str(uuid4()))
    state: MissionState = MissionState.CREATED
    evidence: list[str] = field(default_factory=list)
    audit: list[AuditEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.goal = self.goal.strip()
        self.acceptance_criteria = tuple(item.strip() for item in self.acceptance_criteria if item.strip())
        if not self.goal:
            raise MissionError("Mission goal must not be empty.")
        if not self.acceptance_criteria:
            raise MissionError("At least one acceptance criterion is required.")
        self.record("mission.created", {"criteria_count": len(self.acceptance_criteria)})

    def record(self, event_type: str, details: Mapping[str, Any] | None = None) -> None:
        self.audit.append(AuditEvent(event_type, self.mission_id, details=dict(details or {})))

    def transition(self, target: MissionState, reason: str = "") -> None:
        if target not in TRANSITIONS[self.state]:
            raise MissionError(f"Invalid mission transition: {self.state.value} -> {target.value}")
        previous = self.state
        self.state = target
        self.record("mission.state_changed", {
            "from": previous.value, "to": target.value, "reason": reason[:500]
        })

    def add_evidence(self, item: str) -> None:
        value = item.strip()
        if not value:
            raise MissionError("Evidence must not be empty.")
        if self.state not in {MissionState.RUNNING, MissionState.VERIFYING}:
            raise MissionError("Evidence can only be added while running or verifying.")
        self.evidence.append(value)
        self.record("mission.evidence_added", {"evidence_index": len(self.evidence) - 1})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    read_only: bool = True
    requires_approval: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    effect: PolicyEffect
    reason: str


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    success: bool
    output: Mapping[str, Any]
    audit_event: AuditEvent


class AuthorityKernel:
    """Default-deny policy: only explicitly registered tools can be considered."""

    def decide(self, tool: ToolSpec | None, *, approved: bool = False) -> PolicyDecision:
        if tool is None:
            return PolicyDecision(PolicyEffect.DENY, "Tool is not registered.")
        if not tool.name.strip():
            return PolicyDecision(PolicyEffect.DENY, "Tool name is empty.")
        if tool.requires_approval and not approved:
            return PolicyDecision(PolicyEffect.REQUIRE_APPROVAL, "Explicit approval is required.")
        return PolicyDecision(PolicyEffect.ALLOW, "Tool is registered and policy requirements are met.")


class ToolGateway:
    """Runs only registered in-process handlers; no shell or filesystem access."""

    def __init__(self, authority: AuthorityKernel | None = None) -> None:
        self._authority = authority or AuthorityKernel()
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        name = tool.name.strip()
        if not name or name in self._tools:
            raise MissionError("Tool name must be non-empty and unique.")
        self._tools[name] = tool

    def invoke(
        self,
        mission: Mission,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approved: bool = False,
    ) -> ToolResult:
        spec = self._tools.get(tool_name)
        decision = self._authority.decide(spec, approved=approved)
        mission.record("tool.policy_decision", {
            "tool": tool_name, "effect": decision.effect.value, "reason": decision.reason
        })
        if decision.effect is not PolicyEffect.ALLOW:
            raise MissionError(f"Tool invocation denied: {decision.reason}")
        if mission.state not in {MissionState.RUNNING, MissionState.AWAITING_APPROVAL}:
            raise MissionError("Tools may only be invoked during an active mission.")
        if mission.state is MissionState.AWAITING_APPROVAL:
            mission.transition(MissionState.RUNNING, "Approval satisfied for requested tool.")
        try:
            output = spec.handler(dict(arguments or {}))
            if not isinstance(output, Mapping):
                raise TypeError("Tool handlers must return a mapping.")
            safe_output = dict(output)
            mission.record("tool.invoked", {"tool": tool_name, "success": True})
            return ToolResult(tool_name, True, safe_output, mission.audit[-1])
        except Exception as exc:
            mission.record("tool.invoked", {
                "tool": tool_name, "success": False, "error_type": type(exc).__name__
            })
            raise MissionError(f"Tool '{tool_name}' failed ({type(exc).__name__}).") from exc


def verify_mission(mission: Mission) -> bool:
    """Complete only when every criterion has at least one matching evidence item."""
    if mission.state is not MissionState.VERIFYING:
        raise MissionError("Mission must be in verifying state.")
    if not mission.evidence:
        mission.record("mission.verification_failed", {"reason": "no_evidence"})
        mission.transition(MissionState.FAILED, "No evidence was recorded.")
        return False
    missing = [criterion for criterion in mission.acceptance_criteria if not any(
        criterion.casefold() in evidence.casefold() for evidence in mission.evidence
    )]
    if missing:
        mission.record("mission.verification_failed", {"missing_criteria": missing})
        mission.transition(MissionState.FAILED, "Acceptance criteria lack matching evidence.")
        return False
    mission.record("mission.verification_passed", {"evidence_count": len(mission.evidence)})
    mission.transition(MissionState.COMPLETED, "Every criterion has matching recorded evidence.")
    return True
