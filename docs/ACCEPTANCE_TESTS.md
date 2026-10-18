# ARTA Acceptance Test Plan

**Status:** Mixed: the first rows below have matching local unit tests in tests/test_core.py; remaining requirements are not all implemented and must not be read as passing.

The purpose of this plan is to make the product's most important promises observable and falsifiable. Tests should be deterministic and runnable without real external accounts or live secrets. The current local suite covers mission-state guards, structured evidence, newest/conflicting evidence handling, strict tool argument/target contracts, action-bound approval timing/fingerprints, and safe tool-failure audit behavior.

## 1. Mission state machine

| ID | Scenario | Required result |
| --- | --- | --- |
| FSM-01 | Attempt an undefined state transition | Transition rejected; current state unchanged; safe diagnostic recorded. |
| FSM-02 | Attempt to move from SUCCEEDED, FAILED, or CANCELLED to an active state | Rejected; terminal state preserved. |
| FSM-03 | Mark mission successful without evidence | Rejected; mission stays unverified or blocked. |
| FSM-04 | One mandatory acceptance criterion fails verification | Mission cannot enter SUCCEEDED. |
| FSM-05 | Cancel an executing mission | Cancellation propagates to cancellable work; final status and partial results are reported accurately. |
| FSM-06 | Repeated recovery exceeds configured limits | Mission escalates or fails safely; no infinite loop. |
| FSM-07 | A required human decision is missing | Mission waits for human input; no protected action executes. |

## 2. Authority Kernel and approval

| ID | Scenario | Required result |
| --- | --- | --- |
| AUTH-01 | Invoke a tool absent from the registry | Denied by default. |
| AUTH-02 | Request a registered tool outside its granted scope | Denied; scope and reason code are recorded. |
| AUTH-03 | Policy evaluation fails or is unavailable | Fail closed; no tool invocation occurs. |
| AUTH-04 | State-changing action lacks required approval | Gateway blocks invocation. |
| AUTH-05 | Approved arguments are materially changed before execution | Approval is invalidated and reauthorization is required. |
| AUTH-06 | Agent attempts to grant itself a permission | Denied; permission set remains unchanged. |
| AUTH-07 | User revokes a capability | Subsequent invocations are denied, including queued actions not yet started. |
| AUTH-08 | A persisted approval is consumed by one mission | Another mission cannot reuse it, including after SQLite is reopened. |
| AUTH-09 | Two planned actions reference the same approval id | Whole-plan preflight denies the duplicate before any handler runs. |

## 3. Tool Gateway

| ID | Scenario | Required result |
| --- | --- | --- |
| TOOL-01 | Arguments fail the declared schema | Rejected before adapter invocation. |
| TOOL-02 | Adapter exceeds timeout | Call terminates or is marked uncertain; retry policy is applied without bypassing budgets. |
| TOOL-03 | Adapter returns malformed or unexpected output | Result rejected or marked invalid; verifier cannot treat it as proof. |
| TOOL-04 | A non-idempotent write has uncertain outcome | No blind replay; recovery checks state or requests human review. |
| TOOL-05 | A call exceeds result-size or action budget | Call is stopped or result is bounded; event is recorded. |
| TOOL-06 | Tool failure includes a credential-like value | Secret is redacted from user-facing error and audit output. |

## 4. Workspace containment

| ID | Scenario | Required result |
| --- | --- | --- |
| JAIL-01 | Read or write uses parent traversal to escape the workspace | Rejected and covered by a regression test. |
| JAIL-02 | A symlink points outside the workspace | Access is blocked by robust path and sandbox controls. |
| JAIL-03 | A subprocess exceeds its timeout or resource limit | Process is terminated or contained; cleanup is attempted. |
| JAIL-04 | Tool tries to access an undeclared environment secret | Access is not available by default. |
| JAIL-05 | Cancellation occurs during a write | Result is recorded as complete, partial, or unknown; no false claim of rollback is made. |

## 5. Evidence and reporting

| ID | Scenario | Required result |
| --- | --- | --- |
| EVD-01 | Executor says “done” without supporting evidence | Final report does not claim verified success. |
| EVD-02 | Evidence is stale or refers to a different target | Verifier rejects it or marks the criterion inconclusive. |
| EVD-03 | All required criteria have valid passing evidence | Mission may enter SUCCEEDED. |
| EVD-04 | Evidence is missing or contradictory | Report names the uncertainty and does not overstate completion. |
| EVD-05 | Audit trace is inspected | Policy decision, approval, tool result, and verification can be linked by IDs. |

## 6. Memory and privacy

| ID | Scenario | Required result |
| --- | --- | --- |
| MEM-01 | A model inference is proposed as a user fact | It remains labeled as an inference until confirmed or policy-approved. |
| MEM-02 | User deletes an in-scope memory record | It is removed according to the documented deletion contract; residual copies are covered by retention policy. |
| MEM-03 | Credential-like data is submitted for memory | It is rejected or redacted; it is not persisted as ordinary memory. |
| MEM-04 | A mission in workspace A requests memory from workspace B | Access is denied unless an explicit sharing policy permits it. |

## 7. Provider and integration boundaries

| ID | Scenario | Required result |
| --- | --- | --- |
| INT-01 | An adapter is run in mock mode | Tests do not contact live external services or require live credentials. |
| INT-02 | A connector lacks write permission | Write operation is not offered or is rejected. |
| INT-03 | Remote model use would transmit protected context | User-facing policy/disclosure is applied before transmission. |
| INT-04 | External content contains prompt-injection instructions | The content is treated as untrusted data and cannot modify authorization policy. |

## 8. CI and quality gates

As implementation grows, CI should include:
- formatting, linting, and type checks appropriate to the chosen stack;
- unit tests for state transitions and policy rules;
- integration tests for the orchestrator, gateway, and verifier using mocks;
- security regression tests for path traversal, secret redaction, and approval bypass;
- deterministic fixtures and no dependency on live provider accounts;
- dependency and secret scanning appropriate to the repository's stack.

Test names and outcomes should map to requirement IDs above. A quality gate must not be reported as passing until it has actually run against the relevant revision.


## 9. Newly covered unit-test cases

The current Python suite covers at least these implemented contracts:

- invalid mission creation and illegal/terminal state transitions;
- structured evidence, unknown criteria, duplicate evidence IDs, naive timestamps, missing criteria, newest FAIL/INCONCLUSIVE evidence, and same-time conflict rejection;
- unknown tool denial, allowed/required argument checking, and exact target allowlists;
- missing approval, changed action arguments, changed target/tool, expired/future/revoked approvals, and fingerprint stability;
- rejection of non-finite, circular, non-object, and non-JSON values;
- safe error messages and denial of tool execution outside an active mission.

This section is a map from code to test names, not a statement that the entire acceptance matrix is complete. CI results must be read from the run attached to the exact commit.


## 10. MissionRunner integration tests

The current runner tests additionally check:
- a read-only mission moving from creation through execution, evidence generation, and completion;
- whole-plan preflight: an unapproved write prevents every tool from running, then a correctly approved rerun can complete;
- a denied or unknown later action blocks the whole plan before the first handler runs;
- plan/mission criterion mismatches block execution;
- failed and throwing verifier paths fail closed;
- argument mutation after planning cannot change the action snapshot;
- a tool failure stops later actions and returns a partial-execution report;
- duplicate action IDs are rejected before execution.

The remaining acceptance rows still need implementation and/or independent evidence. JWT claim validation and a Bubblewrap launch boundary now have unit coverage, but the suite does not provide an identity-provider login flow or unconditional proof of sandbox containment on every deployment kernel. Cancellation acknowledgement from real external adapters and real connector tests also remain open.


## 11. SQLite store and durable orchestration tests

The current suite also covers:
- mission snapshot and hash-chained audit round-trips across closing and reopening the database;
- idempotent saves, immutable mission identity, and rejection of divergent in-memory audit prefixes;
- snapshot checksum detection and SQL triggers that reject direct audit-row updates/deletes;
- persisted approval lookup, durable revocation events, duplicate approval rejection, and malformed fingerprints;
- journal status transitions, hash-chained action events, result digests instead of output bodies, and surfaced uncertain outcomes;
- runner checkpoints across execution and verification;
- current persisted revocation defeating a stale approval object supplied by the plan.

Still open: process-kill/crash injection at every boundary, reliable restart reconciliation, enforcement for blocking real external operations, cancellation acknowledgement from real adapters, authenticated multi-user approval, encrypted-at-rest storage, and adversarial tests involving a database-level attacker.


## 12. Cooperative deadlines and cancellation tests

The current suite additionally checks:
- cancellation tokens are idempotent and shared by child execution controls;
- monotonic deadlines expire and child deadlines cannot extend parent deadlines;
- malformed or excessive timeout values are rejected;
- a pre-cancelled mission starts no tool;
- a context-aware handler stops when cancellation or a tool-specific deadline is observed;
- a non-cooperative handler may finish an effect after the deadline, but the mission fails closed and the journal marks the result unknown;
- cancellation during verification creates INCONCLUSIVE evidence and cannot produce a successful mission.

Not covered: killing stuck external processes, forced cancellation of blocking libraries, socket-level timeout behavior for real adapters, or rollback of external side effects.


## 13. Allowlisted workspace adapter tests

The workspace adapter suite must verify:
- only configured relative paths can be read or written;
- absolute paths, traversal, backslashes, symlinked files, and symlinked parent directories are rejected;
- reads reject binary/non-UTF-8 and oversized content;
- creating a file requires the target to be absent;
- replacing a file requires the exact prior SHA-256, and stale hashes are rejected;
- the write tool is approval-gated and a signed approval cannot be replayed for changed arguments;
- successful write reports before/after digests that can be independently checked;
- a failed atomic replacement preserves the old file and cleans temporary artifacts;
- no delete, directory listing, shell, or arbitrary-path operation is exposed.

Boundary not claimed by these tests: resistance to every same-user filesystem race, host-kernel vulnerability, or replacement by a hostile process. Bubblewrap is a separate optional execution component, not an automatic wrapper for WorkspaceAdapter or ToolGateway handlers; its real-kernel integration smoke test remains opt-in and must be run on supported deployments.


## 14. Single-use persisted approval tests

The implementation atomically marks an approval consumed in SQLite before entering its handler. The approval lifecycle event is hash-chained, and consumption is bound to the mission and action fingerprint. Regression tests cover cross-mission reuse, database reopening, projection tampering, and duplicate identifiers during whole-plan preflight.

This closes the prototype's persistence-level replay gap; it does not authenticate the human approver or provide a distributed identity service.

## 15. JWT identity and trusted approval tests

The identity suite must validate:
- only an operator-configured `kid` and asymmetric key/algorithm pair can verify a token;
- bad signatures, algorithm confusion, unknown keys, expired tokens, invalid issuer/audience, missing claims, malformed scopes, and excessive token lifetime are denied;
- approval issuance requires both `arta:approve` and `arta:approve:<tool-name>`, denies unregistered tools, derives approver identity from the verified subject, caps the approval lifetime, and persists an HMAC-attested action;
- authentication/authorization failures do not persist an approval or expose token contents.

These tests validate token claims using generated test keys, not a live identity provider, login flow, JWKS rotation, MFA, or production session-revocation service.

## 16. Bubblewrap isolation tests

The sandbox suite checks:
- no command can be selected outside the trusted executable alias map;
- argument strings remain argv data and cannot become host-shell syntax;
- required user/PID/network/IPC/UTS namespaces, read-only runtime/source mounts, private size-capped workspace/tmpfs, sanitized environment, and resource limits are present in the command;
- a namespace/mount preflight happens before any requested task; failed preflight never launches it;
- timeout kills the supervisor and there is no direct-host fallback;
- output capture is bounded in memory and process output is truncated with an explicit flag;
- an opt-in Linux integration run tries to mutate a host path and reach an external network endpoint while checking that the host marker and source workspace stay unchanged.

The normal CI suite mocks Popen for deterministic lifecycle tests. The opt-in integration test is not counted as passed unless run on a host with Bubblewrap and working user namespaces. Kernel-exploit resistance, hostile same-user processes, and security certification are not claimed.

## 17. ToolGateway sandbox bridge

- registering the bridge marks the process tool non-read-only and approval-required;
- an invocation without approval transitions to the approval-pending state and never calls the sandbox;
- a correctly signed, action-bound approval permits the exact argument snapshot to reach the sandbox adapter;
- an executable alias outside the configured target allowlist is denied before handler execution;
- non-array argv and invalid timeout types are rejected by the adapter;
- command exit status, timeout and output truncation are returned as structured fields for independent mission verification.

These tests use a real BubblewrapSandbox configuration object with its `run` method replaced by a test double. They validate policy wiring only, not kernel-level isolation. The opt-in Bubblewrap integration test must be executed on the deployment host.
