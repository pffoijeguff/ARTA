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
from types import MappingProxyType
from typing import Any, Callable, Mapping
from uuid import uuid4


MAX_TOOL_INVOCATIONS_PER_MISSION = 128


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
    if isinstance(value, (list, tuple)):
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


class _FrozenList(list):
    """List-compatible JSON array that rejects ordinary mutation operations."""

    @staticmethod
    def _deny(*_args: Any, **_kwargs: Any) -> None:
        raise TypeError("Audit event details are immutable.")

    __setitem__ = _deny
    __delitem__ = _deny
    __iadd__ = _deny
    __imul__ = _deny
    append = _deny
    clear = _deny
    extend = _deny
    insert = _deny
    pop = _deny
    remove = _deny
    reverse = _deny
    sort = _deny


def _freeze_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze_json_value(item) for item in value)
    return value


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
        MissionState.AWAITING_APPROVAL, MissionState.VERIFYING, MissionState.FAILED,
        MissionState.BLOCKED, MissionState.CANCELLED,
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

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise MissionError("Audit event type must be a non-empty string.")
        if not isinstance(self.mission_id, str) or not self.mission_id.strip():
            raise MissionError("Audit event mission id must be a non-empty string.")
        try:
            copied = _normalize_json_value(self.details)
        except (TypeError, ValueError):
            raise MissionError("Audit event details must be bounded JSON data.") from None
        if not isinstance(copied, dict):
            raise MissionError("Audit event details must be a JSON object.")
        object.__setattr__(self, "details", _freeze_json_value(copied))


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
    _audit: list[AuditEvent] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.goal, str) or not self.goal.strip():
            raise MissionError("Mission goal must be a non-empty string.")
        self.goal = self.goal.strip()
        if not isinstance(self.mission_id, str) or not self.mission_id.strip():
            raise MissionError("Mission id must be a non-empty string.")
        self.mission_id = self.mission_id.strip()
        if isinstance(self.acceptance_criteria, (str, bytes)) or not isinstance(
            self.acceptance_criteria, (tuple, list)
        ):
            raise MissionError("Acceptance criteria must be a sequence of non-empty strings.")
        if any(not isinstance(item, str) or not item.strip() for item in self.acceptance_criteria):
            raise MissionError("Acceptance criteria must be non-empty strings.")
        self.acceptance_criteria = tuple(item.strip() for item in self.acceptance_criteria)
        if not self.acceptance_criteria:
            raise MissionError("At least one acceptance criterion is required.")
        if len(set(self.acceptance_criteria)) != len(self.acceptance_criteria):
            raise MissionError("Acceptance criteria must be unique.")
        self.record("mission.created", {"criteria_count": len(self.acceptance_criteria)})

    @property
    def audit(self) -> tuple[AuditEvent, ...]:
        """Read-only audit timeline; callers cannot replace, append, or rewrite events."""
        return tuple(self._audit)

    def record(self, event_type: str, details: Mapping[str, Any] | None = None) -> None:
        if not isinstance(event_type, str) or not event_type.strip():
            raise MissionError("Audit event type must be a non-empty string.")
        if details is None:
            copied_details: Mapping[str, Any] = {}
        elif isinstance(details, Mapping):
            copied_details = details
        else:
            raise MissionError("Audit event details must be a mapping.")
        self._audit.append(AuditEvent(event_type.strip(), self.mission_id, details=copied_details))

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
        if not isinstance(self.name, str) or not self.name or self.name != self.name.strip():
            raise MissionError("Tool name must be a non-empty, trimmed string.")
        if not isinstance(self.read_only, bool) or not isinstance(self.requires_approval, bool):
            raise MissionError("read_only and requires_approval must be booleans.")

        for attribute, label in (
            ("allowed_arguments", "Allowed tool argument names"),
            ("required_arguments", "Required tool argument names"),
            ("allowed_targets", "Allowed tool targets"),
        ):
            value = getattr(self, attribute)
            if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
                raise MissionError(f"{label} must be a sequence of non-empty strings.")
            items = tuple(value)
            if any(not isinstance(item, str) or not item or item != item.strip() for item in items):
                raise MissionError(f"{label} must contain only non-empty, trimmed strings.")
            if len(set(items)) != len(items):
                raise MissionError(f"{label} must be unique.")
            object.__setattr__(self, attribute, items)

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
        if not set(self.required_arguments).issubset(self.allowed_arguments):
            raise MissionError("Required tool arguments must be included in allowed_arguments.")
        if self.target_argument is not None:
            if (
                not isinstance(self.target_argument, str)
                or not self.target_argument
                or self.target_argument != self.target_argument.strip()
                or self.target_argument not in self.allowed_arguments
                or not self.allowed_targets
            ):
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
    """Dispatch trusted, registered in-process handlers through an explicit policy boundary.

    This gateway is not an operating-system sandbox. Handler implementations execute with
    the Python process's privileges and must themselves be trusted and narrowly scoped.
    """

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

    @staticmethod
    def _has_pending_approval(mission: Mission, tool_name: str, fingerprint: str) -> bool:
        pending = False
        for event in mission.audit:
            details = event.details
            if details.get("tool") != tool_name or details.get("action_fingerprint") != fingerprint:
                continue
            if event.event_type == "tool.approval_requested":
                pending = True
            elif event.event_type == "tool.approval_consumed":
                pending = False
        return pending

    @staticmethod
    def _approval_was_consumed(mission: Mission, approval_id: str) -> bool:
        return any(
            event.event_type == "tool.approval_consumed"
            and event.details.get("approval_id") == approval_id
            for event in mission.audit
        )

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

        if not isinstance(mission, Mission):
            raise MissionError("Tool invocation requires a Mission instance.")
        if mission.state not in {MissionState.RUNNING, MissionState.AWAITING_APPROVAL}:
            raise MissionError("Tools may only be invoked during an active mission.")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise MissionError("Tool name must be a non-empty string.")
        tool_name = tool_name.strip()

        # Snapshot caller-supplied data once, then authorize and execute that exact copy.
        # This closes a check/use gap in which a mutable Mapping could change after preflight.
        try:
            normalized = _normalized_arguments(arguments)
        except Exception:
            normalized = {}
            decision = PolicyDecision(PolicyEffect.DENY, "Tool arguments are invalid or exceed the allowed size.")
            arguments_valid = False
        else:
            arguments_valid = True
            spec_for_policy = self._tools.get(tool_name)
            decision = self._authority.decide(
                spec_for_policy, arguments=normalized, approval=approval
            )
        spec = self._tools.get(tool_name)
        mission.record("tool.policy_decision", {
            "tool": tool_name, "effect": decision.effect.value, "reason": decision.reason,
            "action_fingerprint": decision.action_fingerprint,
        })
        if not arguments_valid or decision.effect is PolicyEffect.DENY:
            raise MissionError(f"Tool invocation denied: {decision.reason}")

        if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
            if mission.state is MissionState.RUNNING:
                mission.transition(
                    MissionState.AWAITING_APPROVAL,
                    "A registered action requires explicit action-bound approval.",
                )
                mission.record("tool.approval_requested", {
                    "tool": tool_name,
                    "action_fingerprint": decision.action_fingerprint,
                    "reason": decision.reason,
                })
            elif not self._has_pending_approval(
                mission, tool_name, decision.action_fingerprint or ""
            ):
                raise MissionError("Mission is awaiting approval for a different action.")
            raise MissionError(f"Tool invocation requires approval: {decision.reason}")

        requires_approval = spec.requires_approval or not spec.read_only
        invocation_count = sum(
            event.event_type == "tool.invocation_started" for event in mission.audit
        )
        if invocation_count >= MAX_TOOL_INVOCATIONS_PER_MISSION:
            mission.record("mission.action_budget_exhausted", {
                "budget": "tool_invocations",
                "limit": MAX_TOOL_INVOCATIONS_PER_MISSION,
                "attempted_tool": tool_name,
            })
            mission.transition(
                MissionState.BLOCKED,
                "The per-mission tool invocation budget was exhausted.",
            )
            raise MissionError("Mission tool invocation budget exhausted.")

        if requires_approval and approval is None:
            # Normally intercepted by REQUIRE_APPROVAL; keep this guard independent of policy overrides.
            raise MissionError("This action requires a valid action-bound approval.")
        if requires_approval and self._approval_was_consumed(mission, approval.approval_id):
            raise MissionError("This approval record has already been consumed by this mission.")

        if mission.state is MissionState.AWAITING_APPROVAL:
            if (
                not requires_approval
                or approval is None
                or not self._has_pending_approval(
                    mission, tool_name, decision.action_fingerprint or ""
                )
            ):
                raise MissionError("Mission is awaiting approval for a different action.")
            mission.transition(
                MissionState.RUNNING,
                "The exact pending action received a valid action-bound approval.",
            )

        if requires_approval:
            # Consume before entering the handler, preventing a same-mission replay after success
            # or an uncertain/failed execution. This does not authenticate the approval issuer.
            mission.record("tool.approval_consumed", {
                "tool": tool_name,
                "action_fingerprint": decision.action_fingerprint,
                "approval_id": approval.approval_id,
            })

        if execution_control is None:
            control = ExecutionControl(timeout_seconds=spec.timeout_seconds)
        else:
            control = execution_control.child(spec.timeout_seconds)

        mission.record("tool.invocation_started", {
            "tool": tool_name,
            "action_fingerprint": decision.action_fingerprint,
        })
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
            encoded = json.dumps(
                safe_output, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            )
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
