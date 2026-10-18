"""Minimal ARTA mission kernel with explicit evidence and action-bound approvals.

This is an in-memory, dependency-free vertical slice. It does not execute host
commands, access the filesystem, authenticate users, or connect to services.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A timezone-aware ISO-8601 timestamp is required.")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _normalize_json_value(value: Any, *, depth: int = 0, ancestors: set[int] | None = None) -> Any:
    """Copy a strict JSON value and reject cycles, non-finite numbers, and exotic objects."""
    if depth > 32:
        raise ValueError("JSON value exceeds the maximum nesting depth.")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite numbers are not valid action arguments.")
        return value
    if ancestors is None:
        ancestors = set()
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in ancestors:
            raise ValueError("Circular JSON objects are not allowed.")
        ancestors.add(marker)
        try:
            copied: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("All JSON object keys must be strings.")
                copied[key] = _normalize_json_value(item, depth=depth + 1, ancestors=ancestors)
            return copied
        finally:
            ancestors.remove(marker)
    if isinstance(value, list):
        marker = id(value)
        if marker in ancestors:
            raise ValueError("Circular JSON arrays are not allowed.")
        ancestors.add(marker)
        try:
            return [_normalize_json_value(item, depth=depth + 1, ancestors=ancestors) for item in value]
        finally:
            ancestors.remove(marker)
    raise ValueError("Action arguments and tool outputs must use JSON-compatible values only.")


def _normalized_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    if arguments is None:
        return {}
    if not isinstance(arguments, Mapping):
        raise ValueError("Tool arguments must be an object.")
    copied = _normalize_json_value(arguments)
    if not isinstance(copied, dict):
        raise ValueError("Tool arguments must be a JSON object.")
    payload = json.dumps(copied, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(payload.encode("utf-8")) > 64 * 1024:
        raise ValueError("Tool arguments exceed the 64 KiB limit.")
    return copied


class MissionState(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class EvidenceOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class ApprovalStatus(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"


TRANSITIONS = {
    MissionState.CREATED: {
        MissionState.PLANNED, MissionState.BLOCKED, MissionState.FAILED, MissionState.CANCELLED,
    },
    MissionState.PLANNED: {
        MissionState.AWAITING_APPROVAL, MissionState.RUNNING, MissionState.BLOCKED,
        MissionState.FAILED, MissionState.CANCELLED,
    },
    MissionState.AWAITING_APPROVAL: {
        MissionState.RUNNING, MissionState.BLOCKED, MissionState.FAILED, MissionState.CANCELLED,
    },
    MissionState.RUNNING: {
        MissionState.VERIFYING, MissionState.FAILED, MissionState.BLOCKED, MissionState.CANCELLED,
    },
    MissionState.VERIFYING: {
        MissionState.COMPLETED, MissionState.FAILED, MissionState.BLOCKED, MissionState.CANCELLED,
    },
    MissionState.COMPLETED: set(),
    MissionState.BLOCKED: set(),
    MissionState.FAILED: set(),
    MissionState.CANCELLED: set(),
}


class MissionError(ValueError):
    """Raised when a mission operation violates its contract."""


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    mission_id: str
    timestamp: str = field(default_factory=_now)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    """A criterion-scoped verification observation, not a free-form success claim."""

    criterion: str
    outcome: EvidenceOutcome
    source_action_id: str
    summary: str
    observed_at: str = field(default_factory=_now)
    evidence_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class Mission:
    goal: str
    acceptance_criteria: tuple[str, ...]
    mission_id: str = field(default_factory=lambda: str(uuid4()))
    state: MissionState = MissionState.CREATED
    evidence: list[Evidence] = field(default_factory=list)
    audit: list[AuditEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.goal = self.goal.strip()
        self.acceptance_criteria = tuple(item.strip() for item in self.acceptance_criteria if item.strip())
        if not self.goal:
            raise MissionError("Mission goal must not be empty.")
        if not self.acceptance_criteria:
            raise MissionError("At least one acceptance criterion is required.")
        if len(set(self.acceptance_criteria)) != len(self.acceptance_criteria):
            raise MissionError("Acceptance criteria must be unique.")
        self.record("mission.created", {"criteria_count": len(self.acceptance_criteria)})

    def record(self, event_type: str, details: Mapping[str, Any] | None = None) -> None:
        # Avoid persisting arbitrary caller/tool payloads in the audit log.
        self.audit.append(AuditEvent(event_type, self.mission_id, details=dict(details or {})))

    def transition(self, target: MissionState, reason: str = "") -> None:
        if not isinstance(target, MissionState) or target not in TRANSITIONS.get(self.state, set()):
            current = self.state.value if isinstance(self.state, MissionState) else "invalid"
            desired = target.value if isinstance(target, MissionState) else "invalid"
            raise MissionError(f"Invalid mission transition: {current} -> {desired}")
        previous = self.state
        self.state = target
        self.record("mission.state_changed", {
            "from": previous.value, "to": target.value, "reason": str(reason)[:500]
        })

    def add_evidence(self, item: Evidence) -> None:
        if self.state not in {MissionState.RUNNING, MissionState.VERIFYING}:
            raise MissionError("Evidence can only be added while running or verifying.")
        if not isinstance(item, Evidence):
            raise MissionError("Evidence must be a structured Evidence record.")
        if item.criterion not in self.acceptance_criteria:
            raise MissionError("Evidence references an unknown acceptance criterion.")
        if not isinstance(item.outcome, EvidenceOutcome):
            raise MissionError("Evidence outcome must be PASS, FAIL, or INCONCLUSIVE.")
        if not item.evidence_id.strip() or not item.source_action_id.strip() or not item.summary.strip():
            raise MissionError("Evidence id, source action id, and summary must not be empty.")
        try:
            _parse_timestamp(item.observed_at)
        except (ValueError, TypeError):
            raise MissionError("Evidence timestamp must be timezone-aware ISO-8601.") from None
        if any(existing.evidence_id == item.evidence_id for existing in self.evidence):
            raise MissionError("Evidence ids must be unique within a mission.")
        self.evidence.append(item)
        self.record("mission.evidence_added", {
            "evidence_id": item.evidence_id,
            "criterion": item.criterion,
            "outcome": item.outcome.value,
            "source_action_id": item.source_action_id,
        })


@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None
    read_only: bool = True
    requires_approval: bool = False
    allowed_arguments: tuple[str, ...] = ()
    required_arguments: tuple[str, ...] = ()
    target_argument: str | None = None
    allowed_targets: tuple[str, ...] = ()
    timeout_seconds: float | None = None
    contextual_handler: Callable[[Mapping[str, Any], "ExecutionControl"], Mapping[str, Any]] | None = None

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.strip():
            raise MissionError("Tool name must be a non-empty, trimmed string.")
        if (self.handler is None) == (self.contextual_handler is None):
            raise MissionError("Exactly one normal handler or contextual_handler must be provided.")
        if self.handler is not None and not callable(self.handler):
            raise MissionError("Tool handler must be callable.")
        if self.contextual_handler is not None and not callable(self.contextual_handler):
            raise MissionError("contextual_handler must be callable.")
        if self.timeout_seconds is not None:
            if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
                raise MissionError("Tool timeout must be finite, greater than zero, and at most 24 hours.")
            try:
                tool_timeout = float(self.timeout_seconds)
            except (OverflowError, TypeError, ValueError):
                raise MissionError("Tool timeout must be finite, greater than zero, and at most 24 hours.") from None
            if not math.isfinite(tool_timeout) or not 0 < tool_timeout <= 24 * 60 * 60:
                raise MissionError("Tool timeout must be finite, greater than zero, and at most 24 hours.")
        if len(set(self.allowed_arguments)) != len(self.allowed_arguments):
            raise MissionError("Allowed tool argument names must be unique.")
        if not set(self.required_arguments).issubset(self.allowed_arguments):
            raise MissionError("Required tool arguments must be included in allowed_arguments.")
        if self.target_argument is not None:
            if self.target_argument not in self.allowed_arguments or not self.allowed_targets:
                raise MissionError("A target argument must be allowed and have an explicit target allowlist.")
        elif self.allowed_targets:
            raise MissionError("allowed_targets requires target_argument.")


@dataclass(frozen=True)
class PolicyDecision:
    effect: PolicyEffect
    reason: str
    action_fingerprint: str | None = None


@dataclass(frozen=True)
class Approval:
    """Approval assertion from a trusted UI/API boundary; this record does not authenticate its issuer."""

    approval_id: str
    approver_id: str
    action_fingerprint: str
    approved_at: str
    expires_at: str
    status: ApprovalStatus = ApprovalStatus.APPROVED


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    success: bool
    output: Mapping[str, Any]
    audit_event: AuditEvent


def fingerprint_action(tool_name: str, arguments: Mapping[str, Any] | None = None) -> str:
    """Stable SHA-256 fingerprint over a tool name and its complete normalized JSON arguments."""
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("Tool name must not be empty.")
    normalized = _normalized_arguments(arguments)
    payload = json.dumps(
        {"tool": tool_name, "arguments": normalized},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_approval_record(
    tool_name: str,
    arguments: Mapping[str, Any] | None,
    *,
    approver_id: str,
    expires_at: str,
    approved_at: str | None = None,
    approval_id: str | None = None,
) -> Approval:
    """Build an action-bound approval record after the trusted caller authenticates the approver."""
    when = approved_at or _now()
    try:
        approved_time = _parse_timestamp(when)
        expiry_time = _parse_timestamp(expires_at)
        action_hash = fingerprint_action(tool_name, arguments)
    except (ValueError, TypeError):
        raise MissionError("Cannot create approval from invalid action data or timestamps.") from None
    if not isinstance(approver_id, str) or not approver_id.strip():
        raise MissionError("An authenticated approver id is required.")
    if not isinstance(approval_id or "new", str) or not (approval_id or "new").strip():
        raise MissionError("Approval id must not be empty.")
    if expiry_time <= approved_time:
        raise MissionError("Approval expiry must be later than approval time.")
    return Approval(
        approval_id=(approval_id or str(uuid4())).strip(),
        approver_id=approver_id.strip(),
        action_fingerprint=action_hash,
        approved_at=approved_time.isoformat(),
        expires_at=expiry_time.isoformat(),
    )


class AuthorityKernel:
    """Default-deny policy for registered tools, narrow argument contracts, and bounded approvals."""

    def __init__(self, clock: Callable[[], str] | None = None) -> None:
        # Clock injection is configured by the trusted runtime/test harness, never per action.
        self._clock = clock or _now

    def decide(
        self,
        tool: ToolSpec | None,
        *,
        arguments: Mapping[str, Any] | None = None,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        if tool is None:
            return PolicyDecision(PolicyEffect.DENY, "Tool is not registered.")
        if not isinstance(tool, ToolSpec) or not tool.name.strip():
            return PolicyDecision(PolicyEffect.DENY, "Tool descriptor is invalid.")
        try:
            normalized = _normalized_arguments(arguments)
        except (ValueError, TypeError):
            return PolicyDecision(PolicyEffect.DENY, "Tool arguments are invalid or exceed the allowed size.")

        keys = set(normalized)
        if not keys.issubset(tool.allowed_arguments):
            return PolicyDecision(PolicyEffect.DENY, "Action contains arguments not allowed by the tool contract.")
        if not set(tool.required_arguments).issubset(keys):
            return PolicyDecision(PolicyEffect.DENY, "Action is missing required arguments.")
        if tool.target_argument is not None:
            target = normalized.get(tool.target_argument)
            if not isinstance(target, str) or target not in tool.allowed_targets:
                return PolicyDecision(PolicyEffect.DENY, "Action target is outside the tool's explicit allowlist.")

        try:
            action_hash = fingerprint_action(tool.name, normalized)
        except (ValueError, TypeError):
            return PolicyDecision(PolicyEffect.DENY, "Action fingerprint could not be computed.")
        requires_approval = tool.requires_approval or not tool.read_only
        if not requires_approval:
            return PolicyDecision(PolicyEffect.ALLOW, "Registered read-only action matches its contract.", action_hash)
        if approval is None:
            return PolicyDecision(PolicyEffect.REQUIRE_APPROVAL, "An explicit approval bound to this exact action is required.", action_hash)
        if not isinstance(approval, Approval):
            return PolicyDecision(PolicyEffect.DENY, "Approval record is invalid.", action_hash)
        if approval.status is not ApprovalStatus.APPROVED:
            return PolicyDecision(PolicyEffect.DENY, "Approval is denied or revoked.", action_hash)
        if (
            not isinstance(approval.approval_id, str)
            or not approval.approval_id.strip()
            or not isinstance(approval.approver_id, str)
            or not approval.approver_id.strip()
            or not isinstance(approval.action_fingerprint, str)
            or len(approval.action_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in approval.action_fingerprint)
        ):
            return PolicyDecision(PolicyEffect.DENY, "Approval metadata is incomplete or malformed.", action_hash)
        if not hmac.compare_digest(approval.action_fingerprint, action_hash):
            return PolicyDecision(PolicyEffect.DENY, "Approval does not match the requested action.", action_hash)
        try:
            issued = _parse_timestamp(approval.approved_at)
            expiry = _parse_timestamp(approval.expires_at)
            current = _parse_timestamp(self._clock())
        except (ValueError, TypeError):
            return PolicyDecision(PolicyEffect.DENY, "Approval or evaluation timestamp is invalid.", action_hash)
        if expiry <= issued or issued > current or current >= expiry:
            return PolicyDecision(PolicyEffect.DENY, "Approval is expired or not currently valid.", action_hash)
        return PolicyDecision(PolicyEffect.ALLOW, "Exact action, capability contract, and approval are valid.", action_hash)


class ToolGateway:
    """Executes only registered in-process handlers; intentionally no shell or filesystem access."""

    def __init__(self, authority: AuthorityKernel | None = None) -> None:
        self._authority = authority or AuthorityKernel()
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        if not isinstance(tool, ToolSpec):
            raise MissionError("Only validated ToolSpec instances can be registered.")
        if not tool.name or tool.name in self._tools:
            raise MissionError("Tool name must be non-empty and unique.")
        self._tools[tool.name] = tool

    def authorize(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        """Preflight a tool action without executing its handler."""
        spec = self._tools.get(tool_name) if isinstance(tool_name, str) else None
        return self._authority.decide(spec, arguments=arguments, approval=approval)

    def invoke(
        self,
        mission: Mission,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approval: Approval | None = None,
        execution_control: "ExecutionControl | None" = None,
    ) -> ToolResult:
        from .control import ExecutionCancelled, ExecutionControl, ExecutionDeadlineExceeded

        decision = self.authorize(tool_name, arguments=arguments, approval=approval)
        spec = self._tools.get(tool_name) if isinstance(tool_name, str) else None
        mission.record("tool.policy_decision", {
            "tool": tool_name, "effect": decision.effect.value, "reason": decision.reason,
            "action_fingerprint": decision.action_fingerprint,
        })
        if decision.effect is not PolicyEffect.ALLOW:
            raise MissionError(f"Tool invocation denied: {decision.reason}")
        if mission.state not in {MissionState.RUNNING, MissionState.AWAITING_APPROVAL}:
            raise MissionError("Tools may only be invoked during an active mission.")
        if mission.state is MissionState.AWAITING_APPROVAL:
            mission.transition(MissionState.RUNNING, "Approval validated for the exact requested action.")

        if execution_control is None:
            control = ExecutionControl(timeout_seconds=spec.timeout_seconds)
        else:
            control = execution_control.child(spec.timeout_seconds)
        normalized = _normalized_arguments(arguments)
        try:
            control.raise_if_stopped()
            if spec.contextual_handler is not None:
                output = spec.contextual_handler(normalized, control)
            else:
                output = spec.handler(normalized)
            control.raise_if_stopped()
            if not isinstance(output, Mapping):
                raise TypeError("Tool handlers must return a mapping.")
            safe_output = _normalize_json_value(output)
            if not isinstance(safe_output, dict):
                raise TypeError("Tool handlers must return a JSON object.")
            encoded = json.dumps(safe_output, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            if len(encoded.encode("utf-8")) > 256 * 1024:
                raise ValueError("Tool output exceeds the 256 KiB limit.")
            control.raise_if_stopped()
            mission.record("tool.invoked", {"tool": tool_name, "success": True})
            return ToolResult(tool_name, True, safe_output, mission.audit[-1])
        except (ExecutionCancelled, ExecutionDeadlineExceeded) as exc:
            mission.record("tool.invoked", {
                "tool": tool_name, "success": False, "error_type": type(exc).__name__
            })
            raise
        except Exception as exc:
            mission.record("tool.invoked", {
                "tool": tool_name, "success": False, "error_type": type(exc).__name__
            })
            raise MissionError(f"Tool '{tool_name}' failed ({type(exc).__name__}).") from exc


def verify_mission(mission: Mission) -> bool:
    """Complete only when the newest evidence for every criterion is an unambiguous PASS."""
    if mission.state is not MissionState.VERIFYING:
        raise MissionError("Mission must be in verifying state.")
    failed: list[str] = []
    for criterion in mission.acceptance_criteria:
        items = [item for item in mission.evidence if item.criterion == criterion]
        if not items:
            failed.append(criterion)
            continue
        latest_time = max(_parse_timestamp(item.observed_at) for item in items)
        latest = [item for item in items if _parse_timestamp(item.observed_at) == latest_time]
        if not latest or any(item.outcome is not EvidenceOutcome.PASS for item in latest):
            failed.append(criterion)
    if failed:
        mission.record("mission.verification_failed", {"unverified_criteria": failed})
        mission.transition(MissionState.FAILED, "Required criteria lack unambiguous passing evidence.")
        return False
    mission.record("mission.verification_passed", {"evidence_count": len(mission.evidence)})
    mission.transition(MissionState.COMPLETED, "Every criterion has current, explicit passing evidence.")
    return True
