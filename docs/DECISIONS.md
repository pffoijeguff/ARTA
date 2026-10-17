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
