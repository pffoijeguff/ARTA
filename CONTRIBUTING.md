# Contributing to ARTA

Thank you for helping make ARTA more reliable, understandable, and safe.

The repository is currently at the specification/foundation stage. Contributions may improve the architecture, security model, acceptance tests, or a small independently testable implementation as it is introduced.

## Before proposing a change

1. Read the [Architecture](docs/ARCHITECTURE.md), [Security Model](docs/SECURITY_MODEL.md), [Acceptance Tests](docs/ACCEPTANCE_TESTS.md), and [Roadmap](docs/ROADMAP.md).
2. Identify the requirement or user problem the change addresses.
3. Describe observable acceptance criteria, including failure behavior.
4. Consider permissions, privacy, prompt injection, retries, cancellation, and misleading success reports where relevant.
5. Keep the change small enough to review, but complete across the contract, behavior, and tests.

## Engineering expectations

- Do not claim a feature is implemented until its code and evidence exist.
- Never weaken default-deny behavior or bypass the Tool Gateway for convenience.
- Treat model and external-service output as untrusted.
- Do not commit tokens, API keys, cookies, private user data, or real credentials.
- Prefer deterministic tests with synthetic fixtures and mock adapters.
- Test denied and failure paths, not only the happy path.
- Keep secrets out of logs and error messages.
- Document meaningful architecture changes in docs/DECISIONS.md.
- Update acceptance criteria and roadmap status when a change materially affects them.

## Pull request checklist

- [ ] The change has a clear problem statement and bounded scope.
- [ ] Relevant design documents are updated.
- [ ] Acceptance criteria and failure behavior are stated.
- [ ] Tests are included or a clear reason is given when they cannot yet exist.
- [ ] Security and privacy implications have been considered.
- [ ] No secrets or private user data are included.
- [ ] Claims in documentation match the code and checks actually performed.
- [ ] Any known limitation is stated plainly.

## Reporting a vulnerability

Please do not publish credentials, personal data, or a weaponized exploit in a public issue. Use the private reporting guidance in [SECURITY.md](SECURITY.md).
