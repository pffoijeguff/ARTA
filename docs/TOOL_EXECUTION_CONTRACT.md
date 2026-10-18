# Tool execution contract

**Status:** Contract for the current Python mission-kernel prototype. This document does not certify arbitrary plugin code or make in-process callbacks safe.

## 1. Trust classes

| Class | Trust assumption | Required boundary |
| --- | --- | --- |
| Core policy/orchestration | Trusted application code | Reviewed package code; no model-generated dynamic imports or evaluation |
| In-process adapter | Fully trusted code running with the ARTA process privileges | May be registered only by trusted application composition; never accept arbitrary plugin/model code as a callback |
| OS-isolated command | Potentially untrusted command within a narrow contract | BubblewrapSandbox, explicit executable alias allowlist, argv array, private temporary workspace, no host network, bounded resources, fail-closed preflight |
| Remote connector | External service and response are untrusted | Per-connector authenticated adapter, least-privilege credentials, explicit operation/target scopes, timeouts, bounded output, independent verification |

**Important:** ToolGateway authorizes calls and validates contracts; it does not automatically move arbitrary Python callbacks into a process or OS sandbox. A callback registered directly with the gateway executes in-process. Treat it as trusted code with the application's privileges.

## 2. Supported secure command path

For command execution in this prototype, use SecureRuntime as the composition root:

1. Validate a JWT from the configured trusted issuer.
2. Derive the approver identity from the verified subject; never accept an approver ID from model output.
3. Require global and tool-specific scopes.
4. Bind the approval to the exact normalized JSON arguments, cap its lifetime, sign it, and persist it.
5. Preflight the whole mission plan before any action runs.
6. Consume persisted approval before handler entry.
7. Invoke only the configured sandbox.run tool.
8. Require Bubblewrap isolation preflight; never fall back to direct host execution.
9. Pass executable alias and argv as data; do not invoke a host shell.
10. Verify outcomes against mission acceptance criteria independently of exit status or the executor's claim.

SecureRuntime.run() rejects plans containing any tool other than its configured sandbox tool. Its private gateway is not a security boundary against malicious Python code already executing in the same process; Python object privacy is not a sandbox.

## 3. Required contract for future adapters

Before adding a connector or plugin, define and test:

- a stable tool name and versioned input/output schema;
- exact allowed arguments, target identifiers, scopes and operation list;
- whether it reads, writes, publishes, deletes, spends money, changes identity/security, or has other consequential effects;
- the execution class and the trust assumption for the handler code;
- authentication source and credential scope; secrets must not enter model prompts or ordinary audit payloads;
- connection, read, write and total-operation timeouts, output-size limits, rate limits and budget limits;
- idempotency keys or a reconciliation procedure for ambiguous external effects;
- a cancellation contract that distinguishes cooperative cancellation from guaranteed process termination;
- structured error codes and redacted diagnostics;
- independent evidence and acceptance criteria for the claimed result;
- mock tests that never require live credentials, plus a deployment-specific integration test where appropriate.

A new adapter must not self-grant capabilities, change its own allowlist, reinterpret model text as executable shell syntax, or retry uncertain writes without reconciliation.

## 4. Failure semantics

- Unknown tool, unknown target, malformed input, missing approval, stale/revoked/consumed approval, or policy error: deny before side effects.
- Sandbox preflight failure: stop; do not execute directly on the host.
- Nonzero process exit, timeout, truncated output, or incomplete result: report the concrete status and require the verifier to decide whether acceptance criteria passed.
- Started external effect with uncertain outcome: mark the action unknown/blocked and require reconciliation; do not blindly replay.
- Blocking in-process callback: a Python deadline is not guaranteed hard interruption. Production adapters must use interruptible APIs and their own transport/process timeouts.

## 5. Testable acceptance criteria

- SecureRuntime rejects every plan that contains an in-process or unknown tool, with zero sandbox calls.
- An unapproved or argument-tampered sandbox action does not invoke the sandbox.
- A consumed approval cannot be replayed by a second mission.
- The executable alias is checked against the trusted sandbox allowlist and argv is passed without shell interpolation.
- Bubblewrap isolation failure never falls back to direct execution.
- A nonzero exit or timeout is not itself proof that a mission criterion passed.
- Every future connector has a separate test suite and a documented trust note before being enabled.

Existing coverage includes runtime plan rejection, exact-argument approval binding, scope enforcement, approval replay prevention, and a real-host Bubblewrap test on the configured Ubuntu 24.04 CI runner. It does not establish safety for arbitrary callbacks or every deployment kernel.
