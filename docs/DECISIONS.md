# Architecture Decisions

This file records durable design choices. A decision may be revised, but changes should include the reason, migration impact, and affected tests.

## ADR-0001 — Mission-first orchestration

**Status:** Accepted as a design direction.

**Decision:** Represent substantial work as a mission with explicit constraints, acceptance criteria, state, budget, approvals, evidence, and a final report.

**Reason:** Conversation text alone does not provide a reliable execution record or a checkable definition of completion.

**Consequences:** The orchestrator and state machine are core components. Chat history may provide context but cannot replace the mission record.

## ADR-0002 — Evidence-gated success

**Status:** Accepted as a design direction.

**Decision:** A mission may enter SUCCEEDED only when every mandatory acceptance criterion has passing, appropriately scoped evidence.

**Reason:** An agent's verbal assertion must not be confused with a verified external effect.

**Consequences:** Evidence provenance, freshness, and verifier outcomes need explicit data structures and tests. Missing or contradictory evidence must remain visible.

## ADR-0003 — Default-deny tool authority

**Status:** Accepted as a design direction.

**Decision:** All tool invocations pass through a deterministic Authority Kernel and Tool Gateway. Unknown, malformed, out-of-scope, or unauthorized actions fail closed.

**Reason:** Prompt instructions alone cannot enforce least privilege or provide a dependable security boundary.

**Consequences:** Every adapter declares capabilities. Approval is checked at execution time, not merely displayed in the UI.

## ADR-0004 — Human approval for consequential changes

**Status:** Accepted as a design direction.

**Decision:** Destructive, externally visible, hard-to-reverse, permission-changing, or production-changing operations require applicable explicit approval. Agents cannot approve their own escalation.

**Reason:** Autonomy should remain bounded by user authority and the impact of the action.

**Consequences:** Approvals need scope, expiry/invalidating conditions, and linkage to the exact proposed action.

## ADR-0005 — Local-first, model-agnostic routing

**Status:** Accepted as a design direction.

**Decision:** Separate orchestration from any one model provider. Prefer local processing where practical; remote transfer must be governed by configuration and clear disclosure.

**Reason:** Provider choice, availability, cost, privacy, and model capability can change independently of core orchestration.

**Consequences:** Providers require a common contract, capability-aware routing, and explicit error handling. Local-first is a routing objective, not a guarantee that every task can run locally.

## ADR-0006 — Evolution by evaluated proposals, not silent self-modification

**Status:** Accepted as a design direction.

**Decision:** Agents may propose improvements, but production code, policy, privileges, and autonomous behavior change only through isolated evaluation, reviewable diffs, required tests, and human approval.

**Reason:** A system must not weaken its own safety constraints while attempting to improve itself.

**Consequences:** Versioned policies, reproducible tests, and an auditable release process are required before production self-improvement workflows are enabled.


## ADR-0007 — Structured criterion-scoped evidence

**Status:** Accepted.

**Decision:** Verification consumes evidence records with a criterion reference, source-action identifier, timestamp, summary, and explicit PASS / FAIL / INCONCLUSIVE outcome. The most recent observation for every required criterion must pass; conflicting latest outcomes fail closed.

**Reason:** Free-form substring matching can produce false positives and cannot distinguish an observed failure from uncertainty.

**Consequences:** Evidence now has a stable schema and source-action reference. Trust in its producer and independent validation of external effects remain responsibilities of a future trusted verification layer.

## ADR-0008 — Action-bound approval records

**Status:** Accepted.

**Decision:** A protected tool action requires an approval record tied to the stable fingerprint of the exact tool name and complete JSON argument object. The record is rejected if its status is not approved, timestamps are invalid, it is future-dated/expired, or any action argument changes.

**Reason:** A boolean approval flag can be accidentally reused for a different action or target.

**Consequences:** The approval record is stricter but does not authenticate the approver. Only a trusted UI/API boundary may create the record after authenticating user intent; production integration must preserve that trust boundary.


## ADR-0009 — Whole-plan preflight before side effects

**Status:** Accepted.

**Decision:** A mission plan is checked against the acceptance criteria and every action is authorized before the first handler executes. If any action is denied, the plan is blocked with no execution. If one or more actions require approval, the mission pauses with no partial execution and may be retried after action-bound approvals are supplied.

**Reason:** Sequentially discovering a missing permission halfway through a multi-step plan can leave a partial external state that the user did not expect.

**Consequences:** The current runner composes the mission state machine and gateway in memory and stops on the first execution failure. Future durable orchestration must preserve this preflight invariant while also handling approval expiry between preflight and execution, non-idempotent uncertain outcomes, cancellation, and process crashes.


## ADR-0010 — Durable SQLite snapshots and uncertain-action journal

**Status:** Accepted for the prototype.

**Decision:** Persist mission snapshots and approval state in SQLite; append mission, approval, and action lifecycle events to per-aggregate hash chains; and record action status transitions without storing raw tool arguments or result bodies. When an execution outcome is uncertain, expose the journal entry for review and do not auto-retry.

**Reason:** In-memory audit is lost on restart, and retrying a tool after an ambiguous interruption can duplicate an external effect.

**Consequences:** The prototype gains durable state and tamper-evident event sequencing, but not encrypted storage, authenticated approvers, atomic coupling to arbitrary external side effects, or safe automatic resumption. The database and its backups/WAL must be protected as sensitive user data.


## ADR-0011 — Cooperative cancellation, not unsafe thread termination

**Status:** Accepted.

**Decision:** Use a shared thread-safe cancellation token and monotonic deadlines. Context-aware tool handlers receive an ExecutionControl and must poll it. Ordinary synchronous handlers are checked before and after returning; if a deadline/cancellation is detected after the handler starts, the result is marked uncertain and not automatically retried.

**Reason:** Python cannot safely kill an arbitrary running thread, and pretending that a timeout can reverse an external side effect would make retry behavior unsafe.

**Consequences:** The prototype provides deterministic cancellation boundaries for cooperative tools and can distinguish CANCELLED from FAILED. Hard interruption, process isolation, interruptible adapters, external-effect reconciliation, and rollback remain adapter/platform responsibilities.


## ADR-010: Allowlist-only workspace writes

**Decision:** Introduce a narrowly scoped workspace adapter before arbitrary connectors or process execution. It operates only on exact relative paths configured by the trusted application, rejects traversal and symlinked components, limits UTF-8 payload sizes, and requires the current file digest before replacement. The write tool remains non-read-only and approval-gated.

**Rationale:** A constrained, auditable write capability tests the complete policy → approval → tool → before/after verification path without granting arbitrary filesystem or shell access.

**Consequences:** The adapter improves defense in depth but is not an OS sandbox and cannot claim complete protection from hostile same-user races. OS-level containment, authenticated identities, and real-adapter cancellation remain release blockers.


## ADR-0012 — Persisted approvals are single-use

**Status:** Accepted for the prototype.

**Decision:** A persisted action-bound approval is consumed atomically in SQLite before the associated handler is entered. The consumption event is appended to the approval's hash chain and records the mission ID, exact action fingerprint, and timestamp. Reuse is denied globally, not merely within one mission's in-memory audit history.

**Reason:** Per-mission replay protection alone permits a copied approval record to be replayed in a different mission. Conservative stop-and-reapprove behavior is preferable to silently reusing permission after an ambiguous attempt.

**Consequences:** A crash after consumption may spend the approval even if no effect occurred; the user must approve a new attempt. This closes a persistence-level replay path, but does not authenticate `approver_id`, protect against a compromised process/database operator, or create a distributed authorization service.