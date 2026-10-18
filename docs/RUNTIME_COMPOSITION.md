# Secure runtime composition

`SecureRuntime` is the composition root for ARTA's security-sensitive command path. It wires
JWT verification, scoped approval issuance, action-bound HMAC attestations, SQLite persistence,
the AuthorityKernel, the ToolGateway, the Bubblewrap adapter, and the evidence-aware MissionRunner.

## Security properties
- The only registered tool is the configured sandbox command tool; plans containing another tool are rejected.
- Approval issuance requires a valid externally issued JWT with `arta:approve` and
  `arta:approve:sandbox.run`, plus any operator-configured extra scopes.
- Approval is bound to the exact JSON arguments, expires within a bounded interval, is persisted,
  and is consumed atomically by MissionRunner before execution.
- argv is passed as data rather than interpolated into a host shell.
- Bubblewrap preflight must establish isolation or execution fails closed.

## Important limits
The end-to-end tests replace the sandbox runner with a test double. They validate composition,
scope enforcement, argument binding, and replay prevention; they do **not** prove kernel-level
isolation. The opt-in real-host Bubblewrap test remains a release gate. Token issuance, MFA,
remote JWKS rotation, encrypted storage, and security certification are not provided. The HMAC
key and identity configuration must be managed outside the repository and SQLite database.
