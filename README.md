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
- An optional SQLiteMissionStore that checkpoints mission state and evidence, persists action-bound approvals, and keeps hash-chained mission, approval, and action event streams.
- A durable action journal with prepared / started / succeeded / failed / unknown transitions; tool arguments and output bodies are not stored, and actions with uncertain outcomes are surfaced rather than automatically retried.
- A conservative restart-reconciliation API, `MissionRunner.recover_interrupted_mission(mission_id)`: it turns a journal entry left at `started` into `unknown`, classifies `prepared` as interrupted-before-start, blocks a non-terminal mission, and requires human review instead of replaying an action.
- Cooperative mission cancellation and monotonic deadlines, plus optional per-tool timeouts. Context-aware handlers can poll an ExecutionControl object; deadline expiry or cancellation produces a terminal mission result and preserves uncertain-action journal state.
- Exact argument contracts and explicit target allowlists for registered tools; capability lists are copied into immutable tuples to prevent accidental post-registration policy changes.
- One normalized argument snapshot is used for both policy evaluation and execution, closing an ordinary mutable-mapping check/use gap.
- Read-only audit timeline and recursively frozen event details, with persistent hash-chained storage available through SQLite.
- A fixed 128-action limit for each mission plan and a 128 invocation-start budget in the gateway; exhausting the runtime budget blocks the mission instead of continuing indefinitely.
- Action-bound approvals using a stable SHA-256 fingerprint over the tool name and complete JSON arguments; direct gateway calls enter an explicit pending-approval state, record requests and consumption, and reject changed-action or same-mission replay attempts. Approval expiry and revocation are checked against a trusted runtime-configured clock.
- Structured evidence records scoped to an acceptance criterion, with PASS / FAIL / INCONCLUSIVE outcomes, source-action IDs, timestamps, and summaries.
- Verification fails closed if required evidence is missing, the newest evidence fails or is inconclusive, or the latest observations conflict.
- Audit events record policy outcomes, action fingerprints, and evidence metadata without recording raw tool arguments or exception messages.
- Strict JSON input/output validation, nesting and payload-size limits, and tests for malformed/circular/non-finite inputs.
- Automated unit tests for core security invariants, SQLite integrity and revocation, restart persistence, action journaling, and end-to-end orchestration, plus GitHub Actions CI on Python 3.12 and 3.13.

**Important limits:** SQLite persistence is optional; execution and tool handlers still run in-process. Recovery is deliberately conservative, not automatic resume: the mission is blocked for human review because the plan and raw tool results are not persisted. A journal entry marked started/unknown requires reconciliation before any replacement action is considered. Approval records still rely on a trusted caller to authenticate the approver; they are not digital signatures. Hash chains and SQLite triggers are tamper-evident safeguards, not protection against an attacker who can rewrite the database and recompute the chains. The database is not encrypted at rest, so protect its location and do not store secrets in mission goals, evidence summaries, or audit details. ExecutionControl does not forcibly interrupt arbitrary Python callbacks: ordinary handlers are checked before and after returning, while only context-aware handlers can observe cancellation/deadlines mid-operation by polling. There is still no agent/model integration, real filesystem or shell tool, external connector, production UI, or OS sandbox. Do not use this prototype to control consequential real-world actions.

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

### Optional durable mission store

Provide an existing gateway, mission, plan, and verifier to the runner as usual, then add the store:

```python
from arta.persistence import SQLiteMissionStore
from arta.runner import MissionRunner

with SQLiteMissionStore("arta.sqlite3") as store:
    runner = MissionRunner(gateway, store)
    report = runner.run(mission, plan, verifier)
```

Persist an approval through the trusted application boundary with `store.put_approval(approval)`; revocation is recorded with `store.revoke_approval(approval_id, actor_id=..., reason=...)`. When a plan carries an approval and a store is configured, the runner reloads the latest stored status instead of trusting a stale in-memory approval object. The store is an early persistence layer, not an identity provider or encrypted secret vault.

### Allowlisted workspace reads and writes

The optional `WorkspaceAdapter` exposes only explicitly allowlisted UTF-8 files. Reads return a SHA-256 digest; writes are approval-gated through `ToolGateway`, create new files only when absent, and replace existing files only when the caller supplies the exact prior `expected_sha256`. Writes use a sibling temporary file and atomic replacement, enforce a 1 MiB default limit, reject traversal and symlinked path components, and report before/after digests.

```python
from arta.core import AuthorityKernel, ToolGateway
from arta.workspace import WorkspaceAdapter

gateway = ToolGateway(AuthorityKernel(approval_verifier=trusted_approval_verifier))
workspace = WorkspaceAdapter(
    "./workspace",
    allowed_paths=("reports/draft.md", "reports/final.md"),
)
workspace.register(gateway)
```

The application must authenticate the approver and provide a trusted approval verifier. This adapter is not an OS sandbox and does not protect against every hostile same-user process or filesystem race. It intentionally has no delete, directory-listing, shell, or arbitrary-path operation.

### Deadlines and cooperative cancellation

A mission can accept an overall timeout and a cancellation token:

```python
from arta.control import CancellationToken

token = CancellationToken()
report = runner.run(mission, plan, verifier, timeout_seconds=120, cancellation_token=token)
# A coordinating thread or UI can call token.cancel() to request cancellation.
```

A tool can set `timeout_seconds` in its `ToolSpec`. To respond while work is in progress, register a `contextual_handler(arguments, control)` and periodically call `control.raise_if_stopped()`. Do not assume this can kill a blocking library call or roll back an external side effect. If a started action times out or is cancelled, ARTA marks its outcome unknown for review and does not retry it automatically.

## Development direction

The SQLite milestone now persists mission snapshots, approval lifecycle state, hash-chained audit records, and a privacy-minimizing action journal. Recent hardening makes the public mission audit timeline read-only, freezes tool capability allowlists, executes the same argument snapshot that was authorized, records action-specific approval requests and consumption, and enforces an invocation budget. Conservative restart reconciliation is now implemented, but it intentionally blocks rather than resumes a mission whose plan and raw results were not durably stored. The next security milestones are authenticated approval at a trusted API/UI boundary, process-isolated execution for stronger deadlines, and an OS-level workspace sandbox. Cooperative timeouts cannot forcibly stop arbitrary synchronous handlers. The runner remains in-process and mock-friendly; durable data does not itself make execution safe or automatically resumable. See the [roadmap](docs/ROADMAP.md).

## فارسی

**آرتا اُمگا بی‌نهایت** با هدف ساخت یک لایهٔ عملیاتی برای هوش مصنوعی طراحی می‌شود؛ سیستمی که مأموریت را از تعریف هدف تا اجرا، مشاهدهٔ نتیجه، راستی‌آزمایی، بازیابی از خطا و گزارش نهایی مدیریت کند.

تفاوت موردنظر ARTA با یک چت‌بات معمولی این است که «گفتنِ انجام شد» را معادل «واقعاً انجام شدن» نمی‌گیرد. هر اقدام باید مجوز روشن، مرز اجرایی مشخص و نتیجهٔ قابل بررسی داشته باشد. در کارهای حساس، کنترل نهایی در اختیار کاربر می‌ماند.

رابط فارسی و راست‌به‌چپ، پردازش محلی در صورت امکان، انتخاب‌پذیری مدل، تیم عامل‌ها، درگاه ابزار، هستهٔ مجوزدهی، حافظهٔ قابل‌کنترل و آزمایش قابلیت‌ها پیش از پذیرش، از اهداف طراحی پروژه‌اند.

**وضعیت فعلی مخزن:** هستهٔ پایتون اکنون یک هماهنگ‌کنندهٔ اجرایی کوچک، ذخیره‌ساز اختیاری SQLite، دفتر ثبت اقدامات و کنترل همکارانهٔ لغو/مهلت اجرا دارد. ابزارهای همکارانه می‌توانند هنگام اجرا لغو یا مهلت را بررسی کنند؛ توابع همگام معمولی را نمی‌توان به‌زور متوقف کرد. این نمونه محصول کامل ARTA نیست و بازیابی خودکار یا ایمنی اجرای واقعی را تضمین نمی‌کند. سایر قابلیت‌ها همچنان اهداف طراحی‌اند، مگر آن‌که صریحاً پیاده‌سازی‌شده معرفی شده باشند.

## Status and contribution

The project is at the specification/foundation stage with an initial executable mission-kernel slice. Contributions that improve precision, threat coverage, acceptance criteria, and independently testable implementation are especially useful. Please do not describe a feature as implemented until code and evidence support that claim.
