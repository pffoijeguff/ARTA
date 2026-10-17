# ARTA Roadmap

**Status:** Proposed delivery sequence. Completion status must be updated only when repository evidence supports it.

The project should advance through a few meaningful milestones. Each milestone has a narrow end-to-end objective and an exit gate; breadth should follow reliability, not precede it.

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
- timeout, cancellation, and bounded recovery have tested outcomes;
- a clean checkout can run the documented checks.

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
