# ARTA Architecture

**Status:** Hybrid: proposed system architecture plus the implemented limits of the initial Python mission-kernel slice.

This document defines contracts that future code should preserve. It is not a claim that all components already exist. The current executable surface is src/arta/core.py: an in-memory state machine, strict tool contracts, a pure authorization evaluator, action-bound approval records, and structured evidence gating.

## 1. System boundary

ARTA accepts a user-defined mission and coordinates bounded work toward an outcome. It does not treat the language model as the security authority. Models may propose plans, tool arguments, diagnoses, or memory updates; deterministic application code and policy controls must decide what is permitted and what counts as verified.

Proposed flow:

- User / Command Center
- Mission Intake → Requirements and Acceptance Criteria
- Mission Orchestrator ↔ Agent Roles
- Authority Kernel → Tool Gateway
- Approved Adapters / Reach Registry → External Services
- Workspace Jail → Structured Results and Evidence Store
- Truth Engine / Verifier → Mission Report
- User-Governed Memory

All tool-capable paths must pass through the Authority Kernel and Tool Gateway. A model must not be able to invoke a connector directly around that boundary.

## 2. Core components and contracts

### 2.1 Command Center

The UI is the user's control surface, not a source of authority. It should provide a clear mission timeline, pending approvals, action details, evidence, budget and time limits, and final status. The visual direction is a premium, immersive command center rather than a generic chat transcript, but clarity and accessibility take priority over animation.

Requirements:
- Persian RTL support must be designed into layout, navigation, tables, code snippets, and mixed Persian/English text.
- Every pending approval must show the exact action, target, relevant arguments, expected effect, and risk.
- Users must be able to cancel a mission and inspect why an action was denied or a mission was blocked.
- Success, failure, and unverified states must be visually and semantically distinct.

### 2.2 Mission Orchestrator

The orchestrator is responsible for valid state transitions, deadlines, attempt limits, cancellation, and final status. It must not rely on a model's free-form text to decide whether a mission has succeeded.

A mission record should include:
- stable mission ID and creation/update timestamps;
- user goal and structured constraints;
- acceptance criteria and verification plan;
- selected model/provider policy, without storing credentials;
- action budget, time budget, and retry limits;
- current state and transition history;
- approval references, tool-call references, evidence references, and final report;
- cancellation or escalation reason where applicable.

### 2.3 Agent roles

Roles are responsibilities, not necessarily separate model instances. A minimal implementation may use one model with distinct, validated stages.

- **Planner:** creates a bounded plan with dependencies and expected evidence.
- **Executor:** proposes or performs only actions that have passed policy checks.
- **Observer:** interprets structured tool results and identifies discrepancies.
- **Verifier:** checks acceptance criteria using evidence that is independent of the executor's assertion.
- **Recovery agent:** proposes a safe repair when an action fails; cannot bypass permissions or expand its own capability set.
- **Memory curator:** proposes scoped memory changes for approval or policy-controlled storage.

Every role must receive only the context and capabilities it needs. Role separation alone is not a security boundary; enforcement belongs in deterministic application code.

### 2.4 Authority Kernel

The Authority Kernel evaluates an action before execution and returns a structured decision:

- **ALLOW** — policy permits the action within existing scope.
- **REQUIRE_APPROVAL** — execution must pause until a valid approval is recorded.
- **DENY** — the action is outside the permitted capability set or violates policy.

A decision record should include the actor/role, action type, target, scope, policy version, reason code, timestamp, and approval reference if applicable. Denials must be final for that action unless a human or policy administrator changes the relevant authorization. An agent must not be able to self-grant permissions.

### 2.5 Tool Gateway

All tools must expose a declared contract. At minimum the gateway should enforce:
- allowlisted tool identity and action;
- schema validation for arguments and output;
- authorization before invocation;
- per-call timeout, size limit, and resource budget;
- bounded retries and idempotency behavior where applicable;
- structured result and error categories;
- correlation IDs and redacted audit events;
- clear separation between read-only and state-changing operations.

No tool should receive a raw, unrestricted shell or arbitrary network access by default. Capability grants should be narrow, time-bounded where possible, and tied to a workspace or mission.

### 2.6 Workspace Jail

Filesystem and process operations must be restricted to an explicit workspace and capability set. Path normalization, symlink handling, parent-directory traversal, process limits, and environment-variable exposure require defensive tests. A string-prefix path check alone is not a sufficient sandbox.

The initial vertical slice should avoid arbitrary shell execution. OS-level sandboxing or a carefully constrained execution service should be established before enabling higher-risk operations.

### 2.7 Evidence Store and Truth Engine

Evidence is structured data associated with a claim or acceptance criterion. Depending on the action, evidence may include a tool result, an artifact digest, a test result, a timestamp, a source reference, or a before/after state comparison.

Rules:
- Agent narration is not evidence by itself.
- Evidence must have provenance, time, and a reference to the action or criterion it supports.
- Verification should report **PASS**, **FAIL**, or **INCONCLUSIVE** with a reason.
- **SUCCEEDED** is allowed only when all required acceptance criteria have passing evidence.
- Missing evidence must result in an explicit unverified or blocked outcome, not optimistic success.
- Evidence payloads must be redacted when they may contain credentials or private data.

### 2.8 Second Brain / memory

Memory should be user-governed, scoped, and distinguish observed facts from model-generated inferences. Planned controls include:
- per-user and per-workspace scope;
- provenance and last-confirmed timestamps;
- retention and deletion behavior;
- opt-in for sensitive or cross-session memory;
- no silent promotion of a guess into a fact;
- secret filtering before persistence.

Memory retrieval is context, not authority: recalled content cannot override current permission policy.

### 2.9 Reach Layer / Registry

External-service adapters should be replaceable and declare their permissions, data flows, supported operations, rate limits, and failure modes. Potential services include GitHub, YouTube, Instagram, X, and Reddit, but availability and permissible automation vary by service and account.

Connectors must use official or otherwise authorized interfaces and respect access controls, platform rules, and user authorization. The registry must never be used to bypass authentication, access restrictions, or anti-abuse controls. Each adapter should ship with mock tests and explicit read/write capability declarations.

### 2.10 Evolution Lab

The Evolution Lab may suggest prompts, plans, policies, tests, or code changes. Proposed changes must be evaluated in an isolated environment with reproducible tests and a reviewable diff. A human must approve changes that alter production code, privileges, security policy, or the behavior of autonomous execution. No self-modification directly into production.

## 3. Proposed 16-state mission model

These state names form a proposed initial contract and may be refined through documented architecture decisions. State transitions must be validated in code; models cannot assign a state directly.

| State | Meaning |
| --- | --- |
| DRAFTED | Initial mission record exists. |
| CLARIFYING | Material ambiguity or missing constraints are being resolved. |
| READY | Goal, constraints, and acceptance criteria are sufficient to plan. |
| PLANNING | A bounded plan is being produced and checked. |
| PLANNED | A validated plan is ready for authorization. |
| AWAITING_APPROVAL | Required human approval is pending. |
| APPROVED | Required authorization has been recorded for the relevant scope. |
| EXECUTING | An approved action is being executed through the gateway. |
| OBSERVING | Results and telemetry are being collected. |
| VERIFYING | Evidence is being checked against acceptance criteria. |
| RETRYING | An allowed, bounded retry is being prepared. |
| RECOVERING | A safe repair or alternate plan is being evaluated. |
| NEEDS_HUMAN | Autonomous progress is blocked pending human input. |
| SUCCEEDED | All required acceptance criteria have passing evidence. |
| FAILED | The mission cannot meet its criteria within policy and limits. |
| CANCELLED | The user or authorized policy cancelled the mission. |

### Transition invariants

- SUCCEEDED, FAILED, and CANCELLED are terminal states.
- SUCCEEDED requires passing verification evidence for every mandatory criterion.
- Entering a state or performing an action must not silently expand tool permissions.
- Approval is bound to a specific action or clearly described scope; changing the action materially invalidates the approval.
- Retries are limited and must not replay a non-idempotent action blindly.
- NEEDS_HUMAN is an explicit safe stop, not a failure hidden from the user.
- Every state transition records the prior state, next state, reason, timestamp, and mission ID.

## 4. Main data flow

1. Parse the user's goal into a mission record.
2. Confirm constraints, risk level, action budget, and verifiable acceptance criteria.
3. Produce a plan and validate that each step maps to an available tool contract or a human action.
4. Evaluate authorization for each proposed action.
5. Execute only approved actions through the Tool Gateway.
6. Persist structured action results and safe evidence references.
7. Verify the acceptance criteria.
8. Retry or recover only within the configured policy; otherwise escalate.
9. Publish a truthful report including completed work, failed steps, remaining uncertainty, and evidence.
10. Offer memory or evolution proposals separately from mission completion.

## 5. Observability

Every mission and tool call should have a correlation ID. Audit events should capture decisions and outcomes without indiscriminately storing full user content, credentials, or private external-service payloads. Logs must distinguish proposed action, policy decision, approval event, execution request, execution result, verification result, recovery decision, and final mission status.

Telemetry is useful only if access to the telemetry itself is controlled and sensitive values are redacted.

## 6. Required implementation order

The first implementation should demonstrate the end-to-end contract with a mock or read-only tool. State-machine and policy tests come before broad integrations. Add write-capable tools only after denial, approval, cancellation, retry, evidence, and audit invariants are executable tests.

See [Acceptance Tests](ACCEPTANCE_TESTS.md), [Security Model](SECURITY_MODEL.md), and [Roadmap](ROADMAP.md).


## 7. What is implemented now

The current Python slice provides:

- a guarded nine-state mission lifecycle (CREATED, PLANNED, AWAITING_APPROVAL, RUNNING, VERIFYING, and four terminal outcomes: COMPLETED, BLOCKED, FAILED, CANCELLED);
- registered in-process tool handlers with allowed/required argument fields and optional exact target allowlists;
- default-deny handling for unknown tools, malformed JSON arguments, unexpected arguments, missing required values, and disallowed targets;
- action fingerprints that are stable across JSON object-key order and change when arguments change;
- approval records tied to the exact tool and arguments, with approver metadata, explicit status, timezone-aware issue time, and expiry checks;
- criterion-scoped evidence with PASS, FAIL, or INCONCLUSIVE outcomes, source-action references, and timestamp-aware verification;
- bounded JSON input/output checks and structured audit events that can be checkpointed into SQLite hash chains without recording raw tool payloads.

These records do not authenticate an approver, make evidence independently trustworthy, or make persistent audit chains tamper-proof. SQLite persistence is optional; the gateway still invokes registered Python callbacks inside the process and does not connect to a host shell, filesystem, browser, model, or external service. Automatic restart recovery, interruptible external adapters, an OS sandbox, and a UI remain unimplemented.

## 8. Immediate integration requirements

Before adding a real connector, a trusted integration layer must authenticate the approver and persist/revoke approval records; load grants and policies from a protected source; serialize audit events to a protected store; and enforce the Authority Kernel result at the same boundary that executes the action. A tool's return value must not be treated as evidence automatically—the verifier or a separate adapter must create criterion-scoped evidence with traceable provenance.


## 9. MissionRunner: implemented orchestration slice

The MissionRunner composes the mission state machine, ToolGateway, AuthorityKernel, and evidence verifier into a minimal end-to-end path:

1. It validates that the plan covers every declared acceptance criterion.
2. It snapshots each action's normalized JSON arguments when the plan is created.
3. It preflights every action before invoking the first handler. A forbidden action blocks the plan; an action requiring approval moves the mission to AWAITING_APPROVAL without running earlier actions.
4. After all actions pass preflight, it transitions the mission to RUNNING and invokes each registered handler through the gateway.
5. It stops at the first execution failure and reports the failed action while preserving the audit trail.
6. It transitions to VERIFYING and calls the explicit verifier callback for each tool result. A verifier exception or malformed result becomes INCONCLUSIVE.
7. It can reach COMPLETED only through verify_mission, after every required criterion has newest unambiguous PASS evidence.

The plan is an in-memory, single-process object. It does not persist checkpoints and cannot safely resume after process restart. Approval records must come from a trusted caller, and tool handlers remain in-process callbacks. The runner provides composition evidence for the first vertical slice, not a complete production execution platform.


Approval time checks use a clock injected when the AuthorityKernel is constructed by the trusted runtime or test harness. The mission/action request itself cannot supply an evaluation timestamp. Tests use a fixed clock through construction to remain deterministic.


## 10. SQLite persistence and action journal

SQLiteMissionStore is the first durable repository for the prototype. It stores a canonical mission snapshot (goal, acceptance criteria, state, and evidence) and appends new mission audit events only when the local audit history matches the already-persisted prefix. Snapshot checksums detect accidental or uncoordinated edits. Mission, approval, and action-event streams use per-aggregate sequence numbers and a SHA-256 hash chain; SQLite triggers reject ordinary UPDATE and DELETE operations on the event tables.

The approval table persists the exact action fingerprint, approver label, issue/expiry times, and status. Revocation updates the current status in the same transaction as an append-only revocation event. When MissionRunner is configured with a store, it re-reads the current status for an approval referenced by the plan during preflight and immediately before invoking that action.

The action journal records prepared, started, succeeded, failed, and unknown transitions. It stores the tool name, action fingerprint, timestamps, error class, and a digest of a successful result—not raw arguments, exception text, or result bodies. The store exposes started/unknown records through unresolved_actions(); it never retries them automatically.

Persistence does not yet provide a transactional boundary around an external side effect. A process can stop after an action starts or after the side effect but before its result is recorded. Such cases remain uncertain and need operator-led reconciliation. Hash chains are tamper-evident, not an externally anchored ledger; a database administrator who can rewrite all rows and recompute hashes is outside this protection boundary. The database is not encrypted at rest.


## 11. Cooperative execution control

MissionRunner accepts an optional overall timeout and CancellationToken. Each ToolSpec may define a narrower timeout. ToolGateway creates a child ExecutionControl whose monotonic deadline cannot extend the mission deadline; child controls share the same thread-safe cancellation token. The state model distinguishes cancellation from a runtime failure with a terminal CANCELLED state.

Context-aware tools are registered with contextual_handler(arguments, control) and should poll control.raise_if_stopped() during long work. Ordinary one-argument handlers are checked before and after the callback but cannot be interrupted while blocked inside arbitrary synchronous code. A callback can therefore complete an external effect after cancellation/deadline; that action is recorded as unknown, and no automatic retry occurs. Deadlines and cancellation are best-effort execution controls, not an operating-system sandbox or rollback mechanism.
