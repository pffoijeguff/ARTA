# ARTA Roadmap

**Status:** Proposed delivery sequence. Completion status must be updated only when repository evidence supports it.

The project should advance through a few meaningful milestones. Each milestone has a narrow end-to-end objective and an exit gate; breadth should follow reliability, not precede it.

## Progress snapshot — 2026-10-18

The Python kernel includes structured evidence, action-bound approvals, SQLite persistence and recovery, cooperative cancellation, and allowlisted workspace writes. The latest security slice adds configured-key JWT validation and trusted scope-based approval issuance, plus a Linux BubblewrapSandbox that launches allowlisted processes with private tmpfs workspace, no network namespace sharing, and bounded resources. The full product is still a prototype: no login/token-acquisition UI, automatic safe resumption, encrypted storage, interruptible real adapters, real connector runtime, or production Command Center is delivered. Real Bubblewrap integration testing is opt-in and is still a deployment release gate.

## M0 — Project foundation and contracts

**Goal:** Make the intended system understandable, reviewable, and testable before implementation expands.

Deliverables:
- architecture and trust-boundary specification;
- 16-state mission model and explicit success invariant;
- default-deny authorization and approval contract;
- acceptance-test matrix for state, tools, evidence, isolation, and privacy;
- clear status reporting that separates planned requirements from implemented capabilities.

**Exit criteria:** Core documents agree on component boundaries, and every major promise maps to observable acceptance criteria.

## M1 — Verified vertical slice

**Goal:** Demonstrate one mission end-to-end with a mock or read-only tool.

Deliverables:
- typed mission model and transition validator;
- deterministic orchestration of intake, plan, call, observe, verify, and report;
- Tool Gateway contract with one mock/read-only adapter;
- Authority Kernel with default-deny behavior and reason-coded decisions;
- evidence records linked to acceptance criteria;
- structured audit events and secret redaction;
- unit and integration tests runnable without remote accounts.

**Exit criteria:**
- illegal transitions are rejected;
- unknown tools are denied;
- missing approval blocks protected operations;
- a mission cannot report success without passing evidence;
- tool arguments and targets are validated against explicit contracts;
- approvals are action-bound, unexpired, and not revoked;
- timeout, cancellation, and bounded recovery have tested outcomes;
- a clean checkout can run the documented checks.

**Current status:** MissionRunner journaling, cooperative cancellation, and conservative crash/restart reconciliation are tested. JWT verification and a Bubblewrap process boundary now exist as optional components, but this is still not the full M1 release gate: real-host sandbox validation, integration of authenticated identity into an actual UI/API, hard interruption/cancellation acknowledgement for real adapters, and end-to-end production acceptance remain open.

## M2 — Controlled state changes

**Goal:** Introduce one narrowly scoped write-capable tool without weakening core invariants.

Deliverables:
- action-specific approval UI and durable approval records;
- explicit before/after state checks;
- idempotency or safe uncertain-outcome handling;
- workspace containment and cancellation semantics;
- clear audit and user-facing action reports.

**Exit criteria:** Approval-bypass, scope-confusion, replay, cancellation, and partial-write tests pass. A write action cannot broaden its own permissions.

## M3 — Agent coordination and recovery

**Goal:** Add role-based planning, execution, observation, verification, and recovery over the same policy boundary.

Deliverables:
- bounded planner/executor/verifier loops;
- explicit deadlines and step/resource budgets;
- recovery plans that preserve original constraints;
- escalation to NEEDS_HUMAN;
- tests against false-success reports, loops, and prompt injection in untrusted results.

**Exit criteria:** Agent coordination does not bypass the gateway, verifier results are evidence-based, and runaway loops stop within known limits.

## M4 — User-governed memory and provider routing

**Goal:** Add scoped memory and model/provider selection with transparent data handling.

Deliverables:
- local-first routing where practical;
- configurable local and remote providers;
- explicit disclosure for remote data transfers;
- provenance-aware memory with review, retention, and deletion behavior;
- credential filtering and cross-workspace access tests.

**Exit criteria:** Data flows are documented; memory is not treated as authority; deletion and scope constraints have executable tests.

## M5 — Authorized connector registry

**Goal:** Add external connectors one at a time, starting with the lowest-risk useful operation.

Deliverables:
- adapter contracts declaring read/write capabilities;
- mock fixtures and integration tests;
- rate-limit, authentication, and error handling;
- per-connector permission grants and audit reporting;
- documented compliance with each service's authorized interface and rules.

**Exit criteria:** Each connector has independent tests and a reviewed threat note. Unavailable, unauthorized, or forbidden operations fail closed.

## M6 — Command Center and evolution workflow

**Goal:** Deliver a polished user experience and a controlled path for product improvement.

Deliverables:
- mission timeline, evidence explorer, approvals, and recovery visibility;
- Persian RTL and mixed-language rendering checks;
- responsive and accessible interaction states;
- isolated evaluation of proposed prompts, tools, policies, and code;
- human-reviewed diffs and release gates for production changes.

**Exit criteria:** Users can tell what ARTA did, what it did not do, why an action was blocked, and which evidence supports the final result. No proposed change reaches production without required checks and approval.

## Priority rule

Reliability, security, and truthfulness are release blockers. New connectors, animation, and advanced autonomy must not displace state-machine correctness, authorization, containment, and evidence-backed reporting.

The checklist above is not a claim that any milestone is complete. Update milestones only after code, tests, and review evidence exist in the repository.


## Persistence milestone — 2026-10-18

**Delivered:** SQLite mission snapshots with checksums; append-only, hash-chained mission, approval, and action event streams; persisted/revocable action-bound approvals; a journal that tracks prepared/started/succeeded/failed/unknown action states; optional MissionRunner checkpoints; and tests for store reopening, stale approvals, and uncertain action outcomes.

**Delivered since the initial journal:** Conservative recovery through `MissionRunner.recover_interrupted_mission()`. It classifies `prepared` actions as interrupted before handler entry, turns `started` actions into `unknown`, marks any non-terminal mission `BLOCKED`, and emits a durable recovery-required audit event. Repeating recovery is a no-op for already-terminal missions; no tool is replayed.

**Not yet delivered:** Automatic or safe mission resumption after a process crash. The plan and raw tool outputs are not persisted, so resumed execution cannot yet re-establish the exact plan or independently verify past effects. A started/unknown action must be reconciled by a human before any replacement action is planned. Also pending are login/token acquisition and lifecycle management around authenticated approvers, encryption at rest, transactional integrations with real tools, hard interruption of blocking work, and deployment-verified sandbox containment.


## Cooperative execution-control milestone — 2026-10-18

**Delivered:** A thread-safe cancellation token, monotonic mission deadlines, narrower per-tool deadlines, contextual handlers that can poll their execution control, a distinct terminal CANCELLED state, and tests proving that interrupted/expired actions fail closed and are journaled as unknown.

**Boundary:** Python does not safely force-stop arbitrary synchronous callbacks. A standard handler may finish an external effect before the gateway observes the expired deadline. Production adapters must use interruptible APIs and their own socket/process timeout support; the prototype does not claim rollback or hard cancellation.


## Conservative restart-reconciliation milestone — 2026-10-18

**Delivered:** An explicit recovery entry point loads a mission snapshot and its durable action journal, changes a stranded `started` action to `unknown`, classifies a stranded `prepared` action as interrupted before handler entry, records a recovery-required event, and transitions non-terminal missions to `BLOCKED`. It never invokes an action during recovery. Tests cover ambiguous side effects, pre-start interruption, idempotent repeat recovery, and the no-store boundary.

**Boundary:** This is safe stop-and-review behavior, not automatic resumption. The plan and raw tool results are not durably stored, so ARTA must not claim it can resume the exact interrupted execution. A future resumable design needs versioned serialized plans, artifact/result retention policy, idempotency/reconciliation contracts, and explicit human decisions for uncertain external effects.


## Controlled workspace-write milestone — 2026-10-18

**Delivered:** An optional allowlist-only workspace adapter with bounded UTF-8 reads, exact-path policy contracts, traversal/symlink checks, create-only semantics for new files, compare-before-write for replacements, temporary-file staging, atomic replacement, and before/after SHA-256 evidence. The write capability is registered as non-read-only and remains behind the Authority Kernel's exact-action approval gate. Tests cover signed-approval replay resistance, stale-write conflicts, symlinked paths, size limits, and failure cleanup.

**Boundary:** This is a narrow local adapter, not an OS sandbox. It exposes no delete, directory listing, shell, arbitrary path, or process launch. The separate Bubblewrap component offers temporary OS-level process isolation for explicit command tasks, but does not eliminate same-user/host-kernel risks or automatically wrap workspace callbacks. The JWT approval primitive still needs a real login/API integration.


## Single-use persisted-approval milestone — 2026-10-18

**Delivered in this change:** SQLite-backed approvals gain an atomic, append-only `consumed` lifecycle state. Consumption is bound to the exact action fingerprint and persisted mission, runs before handler entry, and cannot be reused across missions or after reopening the store. Whole-plan preflight rejects duplicate approval IDs before execution. Regression tests cover lifecycle integrity, replay after reopening, and a second mission attempting to reuse the same approval.

**Boundary:** This does not establish human identity. Approval creation must still follow real authentication at a trusted UI/API boundary. It is not a substitute for an OS sandbox or a production multi-user authorization service.

## JWT-backed trusted approval milestone — 2026-10-18

**Implemented:** `JwtPrincipalAuthenticator` validates tokens against an operator-configured asymmetric public-key ring, fixed issuer/audience, fixed per-key algorithms, required claims, expiration, issue time, and bounded token lifetime. `TrustedApprovalService` requires global and tool-specific scopes, derives `approver_id` from the verified subject, caps approval lifetime, HMAC-signs the exact action, and persists the signed approval.

**Boundary:** There is no embedded identity provider, login page, OAuth/OIDC token-acquisition flow, remote JWKS fetching/rotation, MFA policy, or session-revocation service. Deployment must provision keys and scopes through a trusted configuration process and must not let models bypass this service.

## Linux Bubblewrap process-boundary milestone — 2026-10-18

**Implemented:** An optional `BubblewrapSandbox` accepts only configured executable aliases, passes argv without a host shell, replaces the host environment, requires user/PID/network/IPC/UTS namespaces, mounts the OS runtime read-only, copies source into size-capped private tmpfs, filters common credential/config filenames and VCS metadata, applies resource limits, caps output in memory, probes isolation before launching the task, and kills the supervisor on wall-clock timeout. Workspace mutations are ephemeral, and unsupported hosts/configurations fail closed rather than executing directly.

**Verification boundary:** Unit tests cover command construction and mocked process lifecycle. A real Bubblewrap integration test is opt-in because user-namespace support varies by host; running it on the deployment kernel and reviewing the concrete runtime configuration remain release gates. The core ToolGateway callbacks remain in-process unless a trusted runtime explicitly routes them to this class. No security certification or protection against kernel exploits is claimed.