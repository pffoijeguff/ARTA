# ARTA Ω∞

[![Documentation checks](https://github.com/pffoijeguff/ARTA/actions/workflows/docs-check.yml/badge.svg)](https://github.com/pffoijeguff/ARTA/actions/workflows/docs-check.yml)

**A Persian-first, local-first AI operating layer for turning missions into verified outcomes.**

ARTA is designed to sit between a user's intent and the tools that can change the world around them. It is not meant to be another chat window or an unchecked automation script. Its target workflow is:

**Goal → requirements → plan → approval → agent team → tools → observation → verification → recovery → learning**

Persian is a first-class interface language, with English technical terminology where it improves precision. The system is intended to be model-agnostic, local-first, transparent about its actions, and governed by explicit user authority.

> **Repository status:** The repository now includes a minimal, executable Python mission-kernel prototype alongside the project specifications. It is not the complete ARTA runtime. The broader capabilities described below remain design goals unless explicitly identified as implemented in the vertical-slice section.

## What ARTA is trying to solve

AI systems can generate useful answers but often struggle to carry out multi-step work reliably: selecting tools, managing permissions, noticing failed actions, checking evidence, recovering safely, and reporting exactly what happened.

ARTA's design goal is to coordinate those steps as a controlled mission rather than treating a model's response as proof of completion.

### Design principles

- **Mission-first:** organize work around a measurable outcome, not an endless conversation.
- **Evidence before success:** a task is not marked successful merely because an agent says it is done.
- **Default-deny authority:** tools receive only the capabilities explicitly permitted by policy.
- **Human control:** ask for approval before consequential, external, destructive, or hard-to-reverse actions.
- **Local-first and model-agnostic:** prefer local processing where practical; make remote-provider use explicit and configurable.
- **Observable execution:** provide a traceable timeline of plans, decisions, tool calls, results, verification, and recovery.
- **Safe recovery:** retry within limits, diagnose failures, and stop for human help instead of bypassing controls.
- **User-owned memory:** keep memory scoped, reviewable, and subject to retention and deletion controls.
- **Persian-first experience:** design for right-to-left Persian from the start while retaining precise English technical terms.

## Target capability map

| Component | Intended responsibility |
| --- | --- |
| Mission Orchestrator | Turn a request into a plan and govern its explicit state transitions. |
| Agent Team | Coordinate planning, execution, observation, verification, recovery, and memory-curation roles. |
| Authority Kernel | Evaluate whether an action is allowed, requires approval, or must be denied. |
| Tool Gateway | Enforce typed tool contracts, timeouts, budgets, and auditable invocation boundaries. |
| Workspace Jail | Constrain filesystem and process access to an explicitly granted workspace. |
| Truth Engine | Attach evidence to claims and prevent unsupported success reports. |
| Second Brain | Store scoped, user-governed memory and distinguish evidence from inference. |
| Reach Layer / Registry | Manage authorized, replaceable connectors and their permissions. |
| Evolution Lab | Evaluate proposed improvements under tests and human approval before adoption. |
| Command Center UI | Present a premium mission view with progress, approvals, evidence, and recovery status. |

These are architecture targets. See [Architecture](docs/ARCHITECTURE.md) and [Security Model](docs/SECURITY_MODEL.md) for the intended contracts and safety boundaries.

## How a mission should work

1. **Define the outcome.** Capture the goal, constraints, budget, deadline, and acceptance criteria.
2. **Resolve ambiguity.** Ask only for details that materially affect safety or the result.
3. **Plan.** Create a bounded plan with dependencies, expected outputs, and verification steps.
4. **Authorize.** Evaluate every action against policy. Pause for approval whenever required.
5. **Execute through the gateway.** Do not give agents unrestricted access to tools or the host environment.
6. **Observe.** Record structured action results and relevant evidence while redacting secrets.
7. **Verify.** Evaluate the result against acceptance criteria independently of the executor's claim.
8. **Recover or escalate.** Use bounded recovery attempts; ask a human when safety or correctness cannot be established.
9. **Report truthfully.** Distinguish completed, failed, blocked, and unverified work.
10. **Learn with consent.** Propose improvements and memory updates; do not silently rewrite production behavior.

## Trust and safety boundary

ARTA is intended to treat all model output, external content, and tool output as potentially untrusted. Policy decisions must be enforced outside the model. High-impact actions require appropriate human approval, secrets must not be committed or casually logged, and integrations must use authorized interfaces.

This repository is not yet a security-certified product. The security document defines intended controls and the [acceptance-test plan](docs/ACCEPTANCE_TESTS.md) describes how they should be checked as implementation begins.

## Repository map

- [Architecture](docs/ARCHITECTURE.md) — components, contracts, mission state machine, and data flow.
- [Security Model](docs/SECURITY_MODEL.md) — trust boundaries, permissions, threat scenarios, and required controls.
- [Acceptance Tests](docs/ACCEPTANCE_TESTS.md) — observable conditions that future implementation must satisfy.
- [Roadmap](docs/ROADMAP.md) — staged delivery with explicit exit criteria.
- [Architecture Decisions](docs/DECISIONS.md) — durable principles and the reasoning behind them.
- [Contributing](CONTRIBUTING.md) — how to propose and review changes.
- [Security Reporting](SECURITY.md) — how to report a vulnerability responsibly.

## First executable vertical slice

The repository now includes a deliberately small Python mission kernel under `src/arta/`. It is the first runnable implementation slice, not the complete ARTA product.

Implemented in this slice:

- A guarded mission state machine with explicit terminal states.
- A default-deny authority decision for unknown tools.
- A tool gateway that only invokes explicitly registered in-process handlers.
- A MissionRunner that preflights the complete plan before any tool runs, pauses when approvals are missing, executes authorized actions, and requests explicit evidence from a verifier callback.
- Exact argument contracts and explicit target allowlists for registered tools.
- Action-bound approvals using a stable SHA-256 fingerprint over the tool name and complete JSON arguments; approvals expire and are rejected if revoked, future-dated, expired, or reused for a changed action.
- Structured evidence records scoped to an acceptance criterion, with PASS / FAIL / INCONCLUSIVE outcomes, source-action IDs, timestamps, and summaries.
- Verification fails closed if required evidence is missing, the newest evidence fails or is inconclusive, or the latest observations conflict.
- Audit events record policy outcomes, action fingerprints, and evidence metadata without recording raw tool arguments or exception messages.
- Strict JSON input/output validation, nesting and payload-size limits, and tests for malformed/circular/non-finite inputs.
- Automated unit tests for core security invariants and end-to-end orchestration, plus GitHub Actions CI on Python 3.12 and 3.13.

**Important limits:** this slice remains in-memory and has no persistent storage, agent/model integration, actual filesystem or shell tools, external connectors, or production UI. An evidence record is still only as trustworthy as the verifier and tool-result producer that create it; it does not independently prove an external fact. Approval records also rely on a trusted caller to authenticate the approver—the record is not a digital signature. Audit events are not tamper-proof. Do not use this prototype to control consequential real-world actions.

### Run locally

Requires Python 3.12 or newer:

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

python -m pip install -e ".[dev]"
python -m pytest -q
```

The CI workflow runs compilation checks, dependency consistency checks, and the test suite. Its result should be verified in GitHub Actions after the workflow executes.

## Development direction

The next milestone is to persist the mission record, approval lifecycle, action results, and audit stream behind a trusted API boundary, then introduce timeouts/cancellation and an OS-level sandbox. The current MissionRunner is deliberately in-process and mock-friendly: it proves the contracts compose, not that real-world automation is safe. Agent/model integration, durable memory, external connectors, and the Command Center UI should follow only after those trust boundaries are tested. See the [roadmap](docs/ROADMAP.md).

## فارسی

**آرتا اُمگا بی‌نهایت** با هدف ساخت یک لایهٔ عملیاتی برای هوش مصنوعی طراحی می‌شود؛ سیستمی که مأموریت را از تعریف هدف تا اجرا، مشاهدهٔ نتیجه، راستی‌آزمایی، بازیابی از خطا و گزارش نهایی مدیریت کند.

تفاوت موردنظر ARTA با یک چت‌بات معمولی این است که «گفتنِ انجام شد» را معادل «واقعاً انجام شدن» نمی‌گیرد. هر اقدام باید مجوز روشن، مرز اجرایی مشخص و نتیجهٔ قابل بررسی داشته باشد. در کارهای حساس، کنترل نهایی در اختیار کاربر می‌ماند.

رابط فارسی و راست‌به‌چپ، پردازش محلی در صورت امکان، انتخاب‌پذیری مدل، تیم عامل‌ها، درگاه ابزار، هستهٔ مجوزدهی، حافظهٔ قابل‌کنترل و آزمایش قابلیت‌ها پیش از پذیرش، از اهداف طراحی پروژه‌اند.

**وضعیت فعلی مخزن:** علاوه بر مستندات پایه، یک نمونهٔ اجرایی کوچک از هستهٔ مأموریت پایتون اضافه شده است؛ این نمونه محصول کامل ARTA نیست. سایر قابلیت‌های مطرح‌شده همچنان اهداف طراحی‌اند، مگر آن‌که صریحاً به‌عنوان پیاده‌سازی‌شده مشخص شده باشند.

## Status and contribution

The project is at the specification/foundation stage with an initial executable mission-kernel slice. Contributions that improve precision, threat coverage, acceptance criteria, and independently testable implementation are especially useful. Please do not describe a feature as implemented until code and evidence support that claim.
