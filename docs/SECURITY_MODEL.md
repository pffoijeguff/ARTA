# ARTA Security Model

**Status:** Requirements for future implementation. These controls are not yet verified in a running ARTA application.

## 1. Security objectives

ARTA should preserve user control, protect credentials and private data, limit the impact of a compromised or mistaken agent, and make every consequential action reviewable.

The primary security principle is **policy outside the model**. Prompt instructions may improve behavior but cannot replace deterministic authorization, sandboxing, or application-side permission checks.

## 2. Assets to protect

- user files, prompts, project workspaces, and generated artifacts;
- access tokens, API keys, cookies, and provider credentials;
- connected accounts and external-service permissions;
- mission histories, evidence, audit events, and personal memory;
- model/provider configuration and local inference resources;
- tool contracts, approval records, policies, and release artifacts.

## 3. Trust boundaries

1. **User ↔ ARTA UI:** user intent, consent, approval, cancellation, and data-transfer disclosures.
2. **Model ↔ orchestrator:** model output is untrusted input and must be schema-validated.
3. **Orchestrator ↔ Authority Kernel:** every action requires an explicit policy decision.
4. **Gateway ↔ tool adapter:** requests are typed, bounded, and logged; results are untrusted.
5. **Workspace ↔ host operating system:** filesystem and process access must be sandboxed.
6. **Local runtime ↔ remote provider:** data sent remotely must follow an explicit provider and privacy policy.
7. **ARTA ↔ external service:** integration uses authorized credentials and allowed operations only.
8. **Runtime ↔ memory store:** persisted data is scoped, reviewable, and subject to retention rules.
9. **Evolution Lab ↔ production:** proposed changes are isolated until tests and required human reviews pass.

## 4. Threat scenarios and required mitigations

| Threat | Required mitigation |
| --- | --- |
| Prompt injection in web pages, files, messages, or tool output | Treat retrieved content as data, not instructions; preserve policy and instruction boundaries; require authorization separately. |
| Model invents success or tool output | Require structured evidence and independent verification before SUCCEEDED. |
| Unauthorized external or destructive action | Default-deny capability policy; approval for consequential actions; action-specific authorization records. |
| Tool argument manipulation | Strict schema validation, allowlisted operations, output validation, and explicit target/scope checks. |
| Path traversal or symlink escape | Canonical path validation and OS-level workspace restrictions; tests for parent traversal, symlinks, and platform-specific paths. |
| Secret leakage through logs, memory, artifacts, or prompts | Secret redaction, minimal collection, dedicated secret storage, exclusion from version control, and controlled retention. |
| Unbounded retry or runaway agent loop | Deadline, step, token/resource, and retry budgets; circuit breakers and clear escalation. |
| Replay of a non-idempotent action | Idempotency keys or precondition checks; explicit recovery design; never blindly replay uncertain writes. |
| Malicious or compromised connector | Narrow capabilities, adapter isolation, pinned dependencies where practical, mock tests, and auditable outputs. |
| Remote-provider data exposure | Local-first routing, explicit disclosure before remote transfer, and configurable provider/data policies. |
| Unsafe self-modification | Isolated candidate evaluation, reproducible tests, reviewable diffs, and human approval before production adoption. |
| Memory poisoning | Provenance, scope boundaries, expiration/review, and separation of user-confirmed facts from model inferences. |

This table is a starting threat model, not proof that these threats are already mitigated.

## 5. Authorization policy

### Default-deny

An action not explicitly registered and permitted is denied. Missing policy, ambiguous target, malformed arguments, unavailable approval state, or policy evaluation failure must fail closed.

### Approval classes

The eventual product should classify actions according to impact. A starting policy:

- **Read-only, bounded action:** may run automatically only when the user has enabled that capability and its scope is clear.
- **External write or publication:** requires clear disclosure of target and effect, and an approval unless the user has granted a narrow, revocable policy for that exact class.
- **Destructive, financial, identity/security, or hard-to-reverse action:** requires explicit, action-specific confirmation and stronger precondition checks.
- **Permission escalation, policy modification, or production self-change:** never approved by an agent acting alone.

An approval is not a general blanket permission. It must be bound to the action or a clearly described scope, and expire or be invalidated when material arguments change.

### Approval record fields

At minimum: approval ID, mission ID, proposed action, normalized target, relevant arguments, expected effect, risk summary, policy version, approver, timestamp, and expiry/scope. Secrets must not be copied into approval UI or logs.

## 6. Data handling

- Do not commit tokens, API keys, browser cookies, private keys, or real user data.
- Load secrets from an appropriate secret store or protected environment configuration, never hard-coded defaults.
- Redact known secret formats before emitting logs or storing memory.
- Do not log full external-service response bodies by default.
- Document what data leaves the device before using a remote model or external connector.
- Define retention and deletion behavior for missions, evidence, logs, and memory.
- Treat all external text and files as potentially adversarial.
- Keep test fixtures synthetic; never use live credentials in tests.

## 7. Workspace and tool isolation

Before enabling arbitrary filesystem writes or process execution, implementation must include:
- explicit workspace roots and robust canonical-path checks;
- traversal and symlink-escape tests;
- process, time, output-size, and resource limits;
- a minimal environment and no ambient credentials;
- an allowlist for executables and arguments if process execution is ever enabled;
- a defined network egress policy;
- cancellation and cleanup behavior for timed-out work.

A workspace path check is not a substitute for an OS-level sandbox.

## 8. Auditability and incident handling

Audit entries should record decision and outcome metadata with correlation IDs, but avoid retaining sensitive payloads unnecessarily. Users should be able to understand what ran, which policy allowed it, whether approval was given, and what evidence supports the report.

For a suspected incident: stop or revoke the affected capability, preserve minimal safe diagnostic evidence, rotate exposed credentials, identify affected missions and data, and document corrective actions. Automated agents must not silently erase audit history.

## 9. Release gate

Do not call a build production-ready until applicable security acceptance tests pass, security-sensitive defaults are reviewed, remote data flows are documented, and unresolved high-severity issues are explicitly handled. No security certification is claimed by this document.


## 10. Implemented controls versus residual risks

The executable Python mission-kernel slice (with optional SQLite persistence) implements exact tool argument allowlists, optional target allowlists, immutable copies of tool capability contracts, strict JSON-compatible argument/output validation, action-bound SHA-256 approval fingerprints, approval status and expiry checks, and explicit evidence outcomes. The public mission audit timeline is returned as a read-only tuple, and event details are recursively frozen against ordinary API-level mutation. The gateway snapshots arguments once and uses that same snapshot for policy evaluation and handler invocation. Direct calls that need approval transition into AWAITING_APPROVAL and emit request/consumption events; an approval record cannot be consumed twice within one mission. Tests cover these invariants alongside altered action arguments, wrong targets, expired/future/revoked approvals, non-JSON inputs, verification gaps, and conflicting/latest evidence.

Important residual risks:
- The caller constructing an Approval record must authenticate the approver; the object is not a signature and cannot establish identity on its own.
- Capability grants are currently embedded in each ToolSpec; no protected policy database, runtime revocation service, or multi-user boundary exists.
- The gateway calls in-process handlers. There is no OS sandbox and no real filesystem, shell, network, browser, or external-service integration.
- Evidence is structured and criterion-scoped, but the code cannot establish that a producer is honest or that a reported external effect is true.
- Mission audit events can be persisted through SQLite hash chains and append-only triggers; the chain is tamper-evident but not tamper-proof, externally anchored, or encrypted at rest. Read-only public access is an API integrity guard, not a security boundary against malicious code running inside the same Python process.
- Authentication, authorization persistence, secret store integration, retention/deletion enforcement, and adversarial end-to-end tests remain outstanding.

The new checks lower several classes of accidental bypass but do not make this prototype suitable for consequential production use.


## 11. Mission orchestration guardrails currently covered

The MissionRunner preflights the entire plan before executing any handler. Missing approvals return the mission to AWAITING_APPROVAL with action IDs, a recorded action-specific approval request, and zero tool executions; any denied action blocks the plan before side effects; immutable plan/gateway argument snapshots prevent ordinary caller-side mutation after approval; and execution stops on the first tool failure. Both the plan and gateway enforce a 128-action/invocation ceiling per mission. Verifier callback errors are converted to INCONCLUSIVE evidence rather than optimistic success.

These are single-process controls. The normal public audit API prevents ordinary accidental event mutation, but Python code with access to the process can still alter private internals or mission state. These controls do not protect against a compromised Python process, malicious in-process handler, forged Approval object, process crash, or tampering with process memory. Do not treat this runner as a sandbox or an authenticated approval service.


The current evaluator now obtains time from an AuthorityKernel clock configured by the trusted runtime or test harness. Per-action requests cannot pass an arbitrary timestamp to make an expired approval appear valid. Production must keep clock configuration outside user-controlled mission data.


## 12. Persistence and interrupted actions

The current SQLite store uses transactions, foreign-key enforcement, full synchronous commits, restrictive file permissions on POSIX systems, snapshot checksums, and per-aggregate SHA-256 hash chains. SQLite triggers make audit-event rows append-only through ordinary SQL operations. The action journal stores an action fingerprint and result digest instead of raw tool arguments or output bodies. The runner checkpoints state around transitions and actions; a stored approval is reloaded so a persisted revocation is not ignored by a stale plan object.

Residual risks:
- SQLite data is not encrypted at rest. Mission goals, acceptance criteria, evidence summaries, and event metadata may contain user data; do not include passwords, API keys, cookies, or other secrets.
- A hash chain detects partial/uncoordinated edits, but it is not an external signature and cannot stop a database-level attacker from rewriting the full database and recomputing the chain.
- File permissions are only one local control; the OS account, backups, WAL files, and parent directory also need protection.
- A crash after a handler begins can leave an action in started or unknown. The explicit recovery API marks stranded started actions unknown, blocks the mission, and never assumes a retry is safe. A stranded prepared action is classified as failed-before-start because the runner persists started before entering the handler.
- The store does not create authenticated identities. The application layer must authenticate approvers before inserting an approval record.
- Revocation is reloaded before the invocation, but this in-process prototype does not make approval lookup and arbitrary side effects one atomic transaction; it is not a multi-user production authorization service.


## 13. Restart reconciliation boundary

`MissionRunner.recover_interrupted_mission(mission_id)` is intentionally a reconciliation operation, not a resumable scheduler. It loads the stored mission and durable action journal, marks entries left at `started` as `unknown`, resolves stranded `prepared` entries as failed-before-start, records a recovery-required audit event, and blocks any non-terminal mission. It does not call tools, repeat writes, infer success from result digests, or construct a replacement plan.

Automatic resumption remains unsafe because the durable snapshot omits the exact versioned execution plan and raw results used by the verifier. Human review must reconcile any uncertain external effect. A future resumable runtime needs explicit idempotency/reconciliation contracts, durable plan/version metadata, and well-defined result/evidence retention before it can safely continue interrupted work.

## 14. Cooperative cancellation and deadline boundary

The prototype uses monotonic deadlines and a thread-safe cancellation token. Mission-wide timeouts are narrowed by optional per-tool timeouts; a contextual handler can poll the shared ExecutionControl while it runs. Cancellation and deadline exceptions are preserved as distinct outcomes in the mission state and the action journal.

This design intentionally does not use unsafe thread termination. A standard synchronous handler cannot be forcibly stopped: the gateway detects cancellation/deadline before and after it returns, which may be after the side effect happened. Such an action is marked unknown and requires review. Hard process isolation, interruptible adapters, network/socket timeouts, external-effect reconciliation, and cancellation acknowledgements remain production requirements.
