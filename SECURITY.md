# Security Policy

## Reporting a vulnerability

Please do not publish credentials, session tokens, private keys, exploitable proof-of-concept payloads, or sensitive production details in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use the repository's **Security** tab and **Report a vulnerability** to submit a private report. If that option is unavailable, contact the repository maintainer through a private contact channel listed on their GitHub profile and share only the minimum information needed to reproduce the issue.

Include, where safe:

- The affected commit, file, component, and deployment assumptions.
- Impact and realistic attacker prerequisites.
- Minimal reproduction steps without real credentials or another person's data.
- Any mitigation already applied.

Please allow time for triage and remediation before public disclosure. This repository is maintained as a project prototype; no formal response-time SLA or bug-bounty program is promised.

## Scope and current limitations

Security-sensitive areas include JWT/OIDC validation, PKCE transaction handling, browser-binding cookies, local session storage and revocation, mission approvals, the tool gateway, and the optional Linux sandbox.

Passing automated tests or CodeQL does not constitute a security certification. The OIDC WSGI adapter requires deployment-specific configuration and review of the identity provider, TLS-terminating proxy, cookie behavior, secret injection, rate limiting, database permissions/backups, and operational logging. Independent security review remains recommended before handling sensitive accounts or consequential actions.
