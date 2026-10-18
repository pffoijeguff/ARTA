"""SQLite persistence for ARTA's early mission kernel.

The store keeps mission snapshots, action-bound approvals, an action journal, and
hash-chained event streams. It intentionally does not persist raw tool arguments
or tool output bodies; only action fingerprints and output digests are journaled.
This is tamper-evident against ordinary edits, not an externally anchored ledger.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Any, Iterator, Mapping

from .core import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    Evidence,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    _normalize_json_value,
    _now,
    _parse_timestamp,
    create_approval_record,
)


_GENESIS_HASH = "0" * 64
_SCHEMA_VERSION = 2
_MAX_EVENT_BYTES = 64 * 1024
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
_TERMINAL_ACTION_STATUSES = {"succeeded", "failed", "unknown"}
_ACTION_TRANSITIONS = {
    None: {"prepared"},
    # A process may crash after recording "prepared" but before recording "started".
    # The handler has not been entered yet, so recovery can classify this as failed-before-start.
    "prepared": {"started", "failed"},
    "started": {"succeeded", "failed", "unknown"},
    "succeeded": set(),
    "failed": set(),
    "unknown": set(),
}


class StoreError(RuntimeError):
    """Raised for persistence contract violations or database failures."""


class StoreIntegrityError(StoreError):
    """Raised when an audit chain or stored snapshot does not verify."""


def _canonical_json(value: Any) -> str:
    try:
        normalized = _normalize_json_value(value)
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise StoreError(f"Value is not valid bounded JSON ({type(exc).__name__}).") from None


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _chain_hash(scope_id: str, sequence: int, previous_hash: str, event_json: str) -> str:
    envelope = f"{scope_id}\n{sequence}\n{previous_hash}\n{event_json}"
    return _digest(envelope)


def _safe_timestamp(value: object, label: str) -> str:
    try:
        parsed = _parse_timestamp(value)
    except (TypeError, ValueError):
        raise StoreError(f"{label} must be a timezone-aware ISO-8601 timestamp.") from None
    return parsed.isoformat()


class SQLiteMissionStore:
    """Small SQLite repository with transactional snapshots and append-only audit chains."""

    def __init__(self, path: str | Path = "arta.sqlite3") -> None:
        raw_path = str(path)
        if not raw_path:
            raise StoreError("Database path must not be empty.")
        if raw_path != ":memory:" and raw_path.startswith("file:"):
            raise StoreError("SQLite URI paths are not accepted by this store.")
        if raw_path != ":memory:":
            target = Path(raw_path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            raw_path = str(target)
        self.path = raw_path
        self._lock = RLock()
        self._connection = sqlite3.connect(
            raw_path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA synchronous = FULL")
        if raw_path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()
        if raw_path != ":memory:" and os.name != "nt":
            try:
                os.chmod(raw_path, 0o600)
            except OSError:
                self.close()
                raise StoreError("Could not restrict database file permissions.") from None

    def _initialize(self) -> None:
        statements = [
            """CREATE TABLE IF NOT EXISTS store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS missions (
                mission_id TEXT PRIMARY KEY,
                goal TEXT NOT NULL,
                criteria_json TEXT NOT NULL,
                state TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS mission_audit_events (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                seq INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                PRIMARY KEY (mission_id, seq)
            )""",
            """CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                approver_id TEXT NOT NULL,
                action_fingerprint TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                signature TEXT,
                record_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS approval_audit_events (
                approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
                seq INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                PRIMARY KEY (approval_id, seq)
            )""",
            """CREATE TABLE IF NOT EXISTS action_journal (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                action_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                action_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_digest TEXT,
                error_type TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (mission_id, action_id)
            )""",
            """CREATE TABLE IF NOT EXISTS action_audit_events (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                seq INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                PRIMARY KEY (mission_id, seq)
            )""",
            """CREATE TRIGGER IF NOT EXISTS mission_audit_no_update
                BEFORE UPDATE ON mission_audit_events
                BEGIN SELECT RAISE(ABORT, 'mission audit is append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS mission_audit_no_delete
                BEFORE DELETE ON mission_audit_events
                BEGIN SELECT RAISE(ABORT, 'mission audit is append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS approval_audit_no_update
                BEFORE UPDATE ON approval_audit_events
                BEGIN SELECT RAISE(ABORT, 'approval audit is append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS approval_audit_no_delete
                BEFORE DELETE ON approval_audit_events
                BEGIN SELECT RAISE(ABORT, 'approval audit is append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS action_audit_no_update
                BEFORE UPDATE ON action_audit_events
                BEGIN SELECT RAISE(ABORT, 'action audit is append-only'); END""",
            """CREATE TRIGGER IF NOT EXISTS action_audit_no_delete
                BEFORE DELETE ON action_audit_events
                BEGIN SELECT RAISE(ABORT, 'action audit is append-only'); END""",
        ]
        with self._lock:
            for statement in statements:
                self._connection.execute(statement)
            self._connection.execute(
                "INSERT OR IGNORE INTO store_meta(key, value) VALUES('schema_version', ?)",
                (str(_SCHEMA_VERSION),),
            )
            version = self._connection.execute(
                "SELECT value FROM store_meta WHERE key='schema_version'"
            ).fetchone()["value"]
            if version == "1":
                # Migration is backwards-compatible with pre-signature approval records.
                columns = {
                    row["name"]
                    for row in self._connection.execute("PRAGMA table_info(approvals)").fetchall()
                }
                if "signature" not in columns:
                    self._connection.execute("ALTER TABLE approvals ADD COLUMN signature TEXT")
                self._connection.execute(
                    "UPDATE store_meta SET value=? WHERE key='schema_version'",
                    (str(_SCHEMA_VERSION),),
                )
                version = str(_SCHEMA_VERSION)
            if version != str(_SCHEMA_VERSION):
                raise StoreError(f"Unsupported database schema version: {version}.")
            self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "SQLiteMissionStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _mission_snapshot(mission: Mission) -> dict[str, Any]:
        if not isinstance(mission, Mission):
            raise StoreError("save_mission requires a Mission object.")
        if not isinstance(mission.mission_id, str) or not mission.mission_id.strip():
            raise StoreError("Mission id must be a non-empty string.")
        if not isinstance(mission.goal, str) or not mission.goal.strip():
            raise StoreError("Mission goal must be a non-empty string.")
        if not isinstance(mission.state, MissionState):
            raise StoreError("Mission state is invalid.")
        criteria = tuple(mission.acceptance_criteria)
        if (
            not criteria
            or any(not isinstance(item, str) or not item.strip() for item in criteria)
            or len(set(criteria)) != len(criteria)
        ):
            raise StoreError("Mission acceptance criteria must be non-empty and unique.")
        evidence_items: list[dict[str, str]] = []
        evidence_ids: set[str] = set()
        parsed_evidence_times = []
        for item in mission.evidence:
            if not isinstance(item, Evidence):
                raise StoreError("Mission contains an invalid evidence record.")
            if item.criterion not in criteria:
                raise StoreError("Evidence references an unknown acceptance criterion.")
            if not isinstance(item.outcome, EvidenceOutcome):
                raise StoreError("Evidence outcome is invalid.")
            if any(
                not isinstance(value, str) or not value.strip()
                for value in (item.evidence_id, item.source_action_id, item.summary)
            ):
                raise StoreError("Evidence id, source action, and summary must be non-empty strings.")
            if item.evidence_id in evidence_ids:
                raise StoreError("Evidence ids must be unique within a mission.")
            evidence_ids.add(item.evidence_id)
            parsed_time = _parse_timestamp(item.observed_at)
            parsed_evidence_times.append((item.criterion, parsed_time, item.outcome))
            evidence_items.append({
                "criterion": item.criterion,
                "outcome": item.outcome.value,
                "source_action_id": item.source_action_id,
                "summary": item.summary,
                "observed_at": parsed_time.isoformat(),
                "evidence_id": item.evidence_id,
            })
        if mission.state is MissionState.COMPLETED:
            for criterion in criteria:
                observations = [
                    (when, outcome)
                    for recorded_criterion, when, outcome in parsed_evidence_times
                    if recorded_criterion == criterion
                ]
                if not observations:
                    raise StoreError("A completed mission must have passing evidence for every criterion.")
                latest_time = max(when for when, _ in observations)
                latest_outcomes = [outcome for when, outcome in observations if when == latest_time]
                if not latest_outcomes or any(outcome is not EvidenceOutcome.PASS for outcome in latest_outcomes):
                    raise StoreError("A completed mission cannot contain missing, failed, or conflicting latest evidence.")
        return {
            "mission_id": mission.mission_id,
            "goal": mission.goal.strip(),
            "acceptance_criteria": list(criteria),
            "state": mission.state.value,
            "evidence": evidence_items,
        }

    @staticmethod
    def _event_payload(event: AuditEvent, mission_id: str) -> dict[str, Any]:
        if not isinstance(event, AuditEvent):
            raise StoreError("Mission audit contains an invalid event.")
        if event.mission_id != mission_id:
            raise StoreError("Audit event mission id does not match the saved mission.")
        if not isinstance(event.event_type, str) or not event.event_type.strip():
            raise StoreError("Audit event type must not be empty.")
        timestamp = _safe_timestamp(event.timestamp, "Audit timestamp")
        details = _normalize_json_value(event.details)
        if not isinstance(details, dict):
            raise StoreError("Audit event details must be a JSON object.")
        payload = {
            "event_type": event.event_type,
            "mission_id": event.mission_id,
            "timestamp": event.timestamp if timestamp else "",
            "details": details,
        }
        encoded = _canonical_json(payload)
        if len(encoded.encode("utf-8")) > _MAX_EVENT_BYTES:
            raise StoreError("Audit event exceeds the 64 KiB size limit.")
        return payload

    def _verify_chain_locked(
        self,
        table: str,
        scope_column: str,
        scope_id: str,
    ) -> list[sqlite3.Row]:
        # Table and column are selected only by private call sites, never user input.
        if (table, scope_column) not in {
            ("mission_audit_events", "mission_id"),
            ("approval_audit_events", "approval_id"),
            ("action_audit_events", "mission_id"),
        }:
            raise StoreError("Unknown audit chain.")
        rows = self._connection.execute(
            f"SELECT seq, event_json, previous_hash, event_hash FROM {table} "
            f"WHERE {scope_column}=? ORDER BY seq",
            (scope_id,),
        ).fetchall()
        previous = _GENESIS_HASH
        for expected_seq, row in enumerate(rows, start=1):
            if row["seq"] != expected_seq:
                raise StoreIntegrityError(f"Audit sequence gap detected for {scope_id}.")
            if row["previous_hash"] != previous:
                raise StoreIntegrityError(f"Audit previous-hash mismatch for {scope_id}.")
            try:
                parsed = json.loads(row["event_json"])
            except (TypeError, json.JSONDecodeError):
                raise StoreIntegrityError(f"Audit event JSON is invalid for {scope_id}.") from None
            if _canonical_json(parsed) != row["event_json"]:
                raise StoreIntegrityError(f"Audit event JSON is not canonical for {scope_id}.")
            expected_hash = _chain_hash(scope_id, expected_seq, previous, row["event_json"])
            if not _is_sha256(row["event_hash"]) or not hmac.compare_digest(expected_hash, row["event_hash"]):
                raise StoreIntegrityError(f"Audit hash mismatch for {scope_id}.")
            previous = row["event_hash"]
        return rows

    def _append_chain_event_locked(
        self,
        table: str,
        scope_column: str,
        scope_id: str,
        event_payload: Mapping[str, Any],
    ) -> None:
        if (table, scope_column) not in {
            ("mission_audit_events", "mission_id"),
            ("approval_audit_events", "approval_id"),
            ("action_audit_events", "mission_id"),
        }:
            raise StoreError("Unknown audit chain.")
        event_json = _canonical_json(event_payload)
        if len(event_json.encode("utf-8")) > _MAX_EVENT_BYTES:
            raise StoreError("Audit event exceeds the 64 KiB size limit.")
        row = self._connection.execute(
            f"SELECT seq, event_hash FROM {table} WHERE {scope_column}=? ORDER BY seq DESC LIMIT 1",
            (scope_id,),
        ).fetchone()
        previous = row["event_hash"] if row else _GENESIS_HASH
        sequence = (row["seq"] + 1) if row else 1
        event_hash = _chain_hash(scope_id, sequence, previous, event_json)
        self._connection.execute(
            f"INSERT INTO {table}({scope_column}, seq, event_json, previous_hash, event_hash) "
            "VALUES(?, ?, ?, ?, ?)",
            (scope_id, sequence, event_json, previous, event_hash),
        )

    def save_mission(self, mission: Mission) -> None:
        """Persist a mission snapshot and append only new, matching audit events."""
        snapshot = self._mission_snapshot(mission)
        snapshot_json = _canonical_json(snapshot)
        if len(snapshot_json.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
            raise StoreError("Mission snapshot exceeds the 2 MiB size limit.")
        snapshot_hash = _digest(snapshot_json)
        criteria_json = _canonical_json(snapshot["acceptance_criteria"])
        local_events = [
            _canonical_json(self._event_payload(event, mission.mission_id))
            for event in mission.audit
        ]
        with self._transaction():
            row = self._connection.execute(
                "SELECT goal, criteria_json FROM missions WHERE mission_id=?",
                (mission.mission_id,),
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO missions(mission_id, goal, criteria_json, state, snapshot_json, "
                    "snapshot_hash, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (
                        mission.mission_id, snapshot["goal"], criteria_json, mission.state.value,
                        snapshot_json, snapshot_hash, _now(),
                    ),
                )
            elif row["goal"] != snapshot["goal"] or row["criteria_json"] != criteria_json:
                raise StoreError("Mission identity is immutable: goal and acceptance criteria cannot change.")

            stored_events = self._verify_chain_locked(
                "mission_audit_events", "mission_id", mission.mission_id
            )
            if len(stored_events) > len(local_events):
                raise StoreError("The in-memory audit history is shorter than the persisted history.")
            for index, event_row in enumerate(stored_events):
                if event_row["event_json"] != local_events[index]:
                    raise StoreError("In-memory audit history diverges from the persisted prefix.")
            for event_json in local_events[len(stored_events):]:
                self._append_chain_event_locked(
                    "mission_audit_events",
                    "mission_id",
                    mission.mission_id,
                    json.loads(event_json),
                )
            self._connection.execute(
                "UPDATE missions SET state=?, snapshot_json=?, snapshot_hash=?, updated_at=? "
                "WHERE mission_id=?",
                (mission.state.value, snapshot_json, snapshot_hash, _now(), mission.mission_id),
            )

    def load_mission(self, mission_id: str) -> Mission | None:
        if not isinstance(mission_id, str) or not mission_id.strip():
            raise StoreError("Mission id must not be empty.")
        with self._lock:
            row = self._connection.execute(
                "SELECT snapshot_json, snapshot_hash FROM missions WHERE mission_id=?",
                (mission_id,),
            ).fetchone()
            if row is None:
                return None
            if not _is_sha256(row["snapshot_hash"]) or not hmac.compare_digest(_digest(row["snapshot_json"]), row["snapshot_hash"]):
                raise StoreIntegrityError(f"Mission snapshot hash mismatch for {mission_id}.")
            event_rows = self._verify_chain_locked(
                "mission_audit_events", "mission_id", mission_id
            )
            try:
                snapshot = json.loads(row["snapshot_json"])
                if _canonical_json(snapshot) != row["snapshot_json"]:
                    raise StoreIntegrityError(f"Mission snapshot JSON is not canonical for {mission_id}.")
                if snapshot["mission_id"] != mission_id:
                    raise StoreIntegrityError(f"Mission snapshot identity mismatch for {mission_id}.")
                mission = Mission(
                    goal=snapshot["goal"],
                    acceptance_criteria=tuple(snapshot["acceptance_criteria"]),
                    mission_id=mission_id,
                )
                mission.state = MissionState(snapshot["state"])
                mission.evidence = [
                    Evidence(
                        criterion=item["criterion"],
                        outcome=EvidenceOutcome(item["outcome"]),
                        source_action_id=item["source_action_id"],
                        summary=item["summary"],
                        observed_at=item["observed_at"],
                        evidence_id=item["evidence_id"],
                    )
                    for item in snapshot["evidence"]
                ]
                mission._audit = []
                for event_row in event_rows:
                    payload = json.loads(event_row["event_json"])
                    mission._audit.append(AuditEvent(
                        event_type=payload["event_type"],
                        mission_id=payload["mission_id"],
                        timestamp=payload["timestamp"],
                        details=payload["details"],
                    ))
            except StoreIntegrityError:
                raise
            except (KeyError, TypeError, ValueError, MissionError):
                raise StoreIntegrityError(f"Mission snapshot or history is invalid for {mission_id}.") from None
            return mission

    def audit_events(self, mission_id: str) -> tuple[AuditEvent, ...]:
        with self._lock:
            rows = self._verify_chain_locked("mission_audit_events", "mission_id", mission_id)
            result: list[AuditEvent] = []
            for row in rows:
                payload = json.loads(row["event_json"])
                result.append(AuditEvent(
                    event_type=payload["event_type"],
                    mission_id=payload["mission_id"],
                    timestamp=payload["timestamp"],
                    details=payload["details"],
                ))
            return tuple(result)

    @staticmethod
    def _approval_payload(approval: Approval) -> dict[str, Any]:
        if not isinstance(approval, Approval):
            raise StoreError("Approval must be an Approval record.")
        if not isinstance(approval.status, ApprovalStatus):
            raise StoreError("Approval status is invalid.")
        for field_name in ("approval_id", "approver_id", "action_fingerprint"):
            value = getattr(approval, field_name)
            if not isinstance(value, str) or not value.strip():
                raise StoreError("Approval id, approver id, and fingerprint must be non-empty strings.")
        if len(approval.action_fingerprint) != 64 or any(
            char not in "0123456789abcdef" for char in approval.action_fingerprint
        ):
            raise StoreError("Approval fingerprint must be a lowercase SHA-256 hex digest.")
        signature = approval.signature
        if signature is not None and (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(char not in "0123456789abcdef" for char in signature)
        ):
            raise StoreError("Approval signature must be a lowercase HMAC-SHA256 hex digest.")
        values = {
            "approval_id": approval.approval_id,
            "approver_id": approval.approver_id,
            "action_fingerprint": approval.action_fingerprint,
            "approved_at": _safe_timestamp(approval.approved_at, "Approval issue time"),
            "expires_at": _safe_timestamp(approval.expires_at, "Approval expiry"),
            "status": approval.status.value,
            "signature": signature,
        }
        if values["expires_at"] <= values["approved_at"]:
            raise StoreError("Approval expiry must be later than issue time.")
        return values

    def put_approval(self, approval: Approval) -> None:
        """Persist a newly issued approval; approval identity is immutable."""
        payload = self._approval_payload(approval)
        if approval.status is not ApprovalStatus.APPROVED:
            raise StoreError("Only an approved record may be inserted; use revoke_approval for revocation.")
        record_json = _canonical_json(payload)
        record_hash = _digest(record_json)
        with self._transaction():
            existing = self._connection.execute(
                "SELECT approval_id FROM approvals WHERE approval_id=?",
                (approval.approval_id,),
            ).fetchone()
            if existing:
                raise StoreError("Approval id already exists.")
            self._connection.execute(
                "INSERT INTO approvals(approval_id, approver_id, action_fingerprint, approved_at, "
                "expires_at, status, signature, record_hash, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    approval.approval_id, approval.approver_id, approval.action_fingerprint,
                    payload["approved_at"], payload["expires_at"], approval.status.value,
                    payload["signature"], record_hash, _now(),
                ),
            )
            event = {
                "kind": "created",
                "approval": payload,
                "recorded_at": _now(),
            }
            self._append_chain_event_locked(
                "approval_audit_events", "approval_id", approval.approval_id, event
            )

    def create_and_store_approval(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        *,
        approver_id: str,
        expires_at: str,
        approval_id: str | None = None,
    ) -> Approval:
        """Create an action-bound approval at the trusted application boundary, then persist it."""
        approval = create_approval_record(
            tool_name,
            arguments,
            approver_id=approver_id,
            expires_at=expires_at,
            approval_id=approval_id,
        )
        self.put_approval(approval)
        return approval

    def get_approval(self, approval_id: str) -> Approval | None:
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise StoreError("Approval id must not be empty.")
        with self._lock:
            row = self._connection.execute(
                "SELECT approval_id, approver_id, action_fingerprint, approved_at, expires_at, "
                "status, signature, record_hash FROM approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
            if row is None:
                return None
            rows = self._verify_chain_locked(
                "approval_audit_events", "approval_id", approval_id
            )
            if not rows:
                raise StoreIntegrityError(f"Approval audit history is missing for {approval_id}.")
            creation = json.loads(rows[0]["event_json"])
            original = {
                "approval_id": row["approval_id"],
                "approver_id": row["approver_id"],
                "action_fingerprint": row["action_fingerprint"],
                "approved_at": row["approved_at"],
                "expires_at": row["expires_at"],
                "status": ApprovalStatus.APPROVED.value,
            }
            # Older schema-v1 creation events predate the signature field; preserve their
            # original hash envelope instead of rewriting an append-only event chain.
            if "signature" in creation.get("approval", {}):
                original["signature"] = row["signature"]
            if creation.get("kind") != "created" or creation.get("approval") != original:
                raise StoreIntegrityError(f"Approval creation record mismatch for {approval_id}.")
            if not _is_sha256(row["record_hash"]) or not hmac.compare_digest(_digest(_canonical_json(original)), row["record_hash"]):
                raise StoreIntegrityError(f"Approval record hash mismatch for {approval_id}.")
            expected_status = ApprovalStatus.APPROVED
            for event_row in rows[1:]:
                event = json.loads(event_row["event_json"])
                if event.get("kind") == "revoked" and expected_status is ApprovalStatus.APPROVED:
                    expected_status = ApprovalStatus.REVOKED
                else:
                    raise StoreIntegrityError(f"Approval lifecycle event is invalid for {approval_id}.")
            if row["status"] != expected_status.value:
                raise StoreIntegrityError(f"Approval status does not match its event history for {approval_id}.")
            return Approval(
                approval_id=row["approval_id"],
                approver_id=row["approver_id"],
                action_fingerprint=row["action_fingerprint"],
                approved_at=row["approved_at"],
                expires_at=row["expires_at"],
                status=ApprovalStatus(row["status"]),
                signature=row["signature"],
            )

    def revoke_approval(self, approval_id: str, *, actor_id: str, reason: str) -> Approval:
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise StoreError("A revocation actor id is required.")
        if not isinstance(reason, str) or not reason.strip():
            raise StoreError("A revocation reason is required.")
        with self._transaction():
            row = self._connection.execute(
                "SELECT approval_id, approver_id, action_fingerprint, approved_at, expires_at, "
                "status, signature, record_hash FROM approvals WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise StoreError("Approval was not found.")
            # Verify the chain and lifecycle before making any change.
            rows = self._verify_chain_locked("approval_audit_events", "approval_id", approval_id)
            if not rows:
                raise StoreIntegrityError(f"Approval audit history is missing for {approval_id}.")
            if row["status"] != ApprovalStatus.APPROVED.value:
                raise StoreError("Only an active approval may be revoked.")
            if len(rows) != 1:
                raise StoreIntegrityError(f"Approval lifecycle and status projection disagree for {approval_id}.")
            creation = json.loads(rows[0]["event_json"])
            original = {
                "approval_id": row["approval_id"],
                "approver_id": row["approver_id"],
                "action_fingerprint": row["action_fingerprint"],
                "approved_at": row["approved_at"],
                "expires_at": row["expires_at"],
                "status": ApprovalStatus.APPROVED.value,
            }
            if "signature" in creation.get("approval", {}):
                original["signature"] = row["signature"]
            if creation.get("kind") != "created" or creation.get("approval") != original:
                raise StoreIntegrityError(f"Approval creation record mismatch for {approval_id}.")
            if not hmac.compare_digest(_digest(_canonical_json(original)), row["record_hash"]):
                raise StoreIntegrityError(f"Approval record hash mismatch for {approval_id}.")
            event = {
                "kind": "revoked",
                "approval_id": approval_id,
                "actor_id": actor_id.strip(),
                "reason": reason.strip()[:500],
                "recorded_at": _now(),
            }
            self._append_chain_event_locked(
                "approval_audit_events", "approval_id", approval_id, event
            )
            self._connection.execute(
                "UPDATE approvals SET status=?, updated_at=? WHERE approval_id=?",
                (ApprovalStatus.REVOKED.value, _now(), approval_id),
            )
        approval = self.get_approval(approval_id)
        if approval is None:
            raise StoreIntegrityError(f"Revoked approval disappeared: {approval_id}.")
        return approval

    def record_action_event(
        self,
        mission_id: str,
        action_id: str,
        tool_name: str,
        action_fingerprint: str,
        status: str,
        *,
        result: Mapping[str, Any] | None = None,
        error_type: str | None = None,
    ) -> None:
        """Persist a status transition without storing raw arguments, output, or exception text."""
        if not all(isinstance(value, str) and value.strip() for value in (mission_id, action_id, tool_name)):
            raise StoreError("Mission, action, and tool ids must be non-empty strings.")
        if (
            not isinstance(action_fingerprint, str)
            or len(action_fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in action_fingerprint)
        ):
            raise StoreError("Action fingerprint must be a lowercase SHA-256 hex digest.")
        if not isinstance(status, str) or status not in _ACTION_TRANSITIONS:
            raise StoreError("Unknown action journal status.")
        if status in {"failed", "unknown"} and (
            not isinstance(error_type, str) or not error_type.strip()
        ):
            raise StoreError("Failed or unknown actions require an error type, not an error message.")
        result_digest: str | None = None
        if result is not None:
            normalized = _normalize_json_value(result)
            if not isinstance(normalized, dict):
                raise StoreError("Tool result must be a JSON object.")
            result_json = _canonical_json(normalized)
            if len(result_json.encode("utf-8")) > 256 * 1024:
                raise StoreError("Tool result exceeds the 256 KiB digesting limit.")
            result_digest = _digest(result_json)
        if status == "succeeded" and result_digest is None:
            raise StoreError("Successful action records require a tool result for digesting.")
        if status != "succeeded" and result is not None:
            raise StoreError("Only successful action records may include a tool result.")

        timestamp = _now()
        with self._transaction():
            if not self._connection.execute(
                "SELECT 1 FROM missions WHERE mission_id=?", (mission_id,)
            ).fetchone():
                raise StoreError("Mission must be persisted before an action can be journaled.")
            row = self._connection.execute(
                "SELECT tool_name, action_fingerprint, status, started_at, finished_at, "
                "result_digest, error_type FROM action_journal WHERE mission_id=? AND action_id=?",
                (mission_id, action_id),
            ).fetchone()
            prior = row["status"] if row else None
            if status not in _ACTION_TRANSITIONS.get(prior, set()):
                raise StoreError(f"Invalid action journal transition: {prior} -> {status}.")
            if row and (row["tool_name"] != tool_name or row["action_fingerprint"] != action_fingerprint):
                raise StoreError("An action id cannot be reused for different tool arguments.")
            self._verify_chain_locked("action_audit_events", "mission_id", mission_id)
            event = {
                "action_id": action_id,
                "tool_name": tool_name,
                "action_fingerprint": action_fingerprint,
                "status": status,
                "timestamp": timestamp,
                "result_digest": result_digest,
                "error_type": error_type.strip()[:120] if isinstance(error_type, str) else None,
            }
            self._append_chain_event_locked(
                "action_audit_events", "mission_id", mission_id, event
            )
            started_at = row["started_at"] if row else None
            finished_at = row["finished_at"] if row else None
            if status == "started":
                started_at = timestamp
            if status in _TERMINAL_ACTION_STATUSES:
                finished_at = timestamp
            self._connection.execute(
                """INSERT INTO action_journal(
                    mission_id, action_id, tool_name, action_fingerprint, status,
                    started_at, finished_at, result_digest, error_type, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mission_id, action_id) DO UPDATE SET
                    status=excluded.status,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    result_digest=excluded.result_digest,
                    error_type=excluded.error_type,
                    updated_at=excluded.updated_at""",
                (
                    mission_id, action_id, tool_name, action_fingerprint, status,
                    started_at, finished_at, result_digest, event["error_type"], timestamp,
                ),
            )

    def action_journal(self, mission_id: str) -> tuple[dict[str, Any], ...]:
        """Return verified action projections for a mission."""
        with self._lock:
            event_rows = self._verify_chain_locked("action_audit_events", "mission_id", mission_id)
            latest: dict[str, dict[str, Any]] = {}
            for row in event_rows:
                event = json.loads(row["event_json"])
                latest[event["action_id"]] = event
            projections = self._connection.execute(
                "SELECT action_id, tool_name, action_fingerprint, status, started_at, finished_at, "
                "result_digest, error_type FROM action_journal WHERE mission_id=?",
                (mission_id,),
            ).fetchall()
            by_id = {row["action_id"]: row for row in projections}
            if set(by_id) != set(latest):
                raise StoreIntegrityError(f"Action journal projection mismatch for {mission_id}.")
            result: list[dict[str, Any]] = []
            for action_id, event in latest.items():
                row = by_id[action_id]
                events_for_action = [
                    json.loads(event_row["event_json"])
                    for event_row in event_rows
                    if json.loads(event_row["event_json"])["action_id"] == action_id
                ]
                expected_started = next(
                    (item["timestamp"] for item in events_for_action if item["status"] == "started"),
                    None,
                )
                expected_finished = next(
                    (
                        item["timestamp"] for item in reversed(events_for_action)
                        if item["status"] in _TERMINAL_ACTION_STATUSES
                    ),
                    None,
                )
                if (
                    row["tool_name"] != event["tool_name"]
                    or row["action_fingerprint"] != event["action_fingerprint"]
                    or row["status"] != event["status"]
                    or row["result_digest"] != event["result_digest"]
                    or row["error_type"] != event["error_type"]
                    or row["started_at"] != expected_started
                    or row["finished_at"] != expected_finished
                ):
                    raise StoreIntegrityError(f"Action journal state mismatch for {action_id}.")
                result.append({
                    "mission_id": mission_id,
                    "action_id": action_id,
                    "tool_name": row["tool_name"],
                    "action_fingerprint": row["action_fingerprint"],
                    "status": row["status"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "result_digest": row["result_digest"],
                    "error_type": row["error_type"],
                })
            return tuple(sorted(result, key=lambda item: item["action_id"]))

    def unresolved_actions(self, mission_id: str | None = None) -> tuple[dict[str, Any], ...]:
        """List actions whose execution may be incomplete or whose effect is uncertain."""
        if mission_id is not None:
            return tuple(
                item for item in self.action_journal(mission_id)
                if item["status"] in {"started", "unknown"}
            )
        with self._lock:
            ids = [
                row["mission_id"]
                for row in self._connection.execute(
                    "SELECT DISTINCT mission_id FROM action_journal ORDER BY mission_id"
                ).fetchall()
            ]
        return tuple(
            item
            for current_id in ids
            for item in self.unresolved_actions(current_id)
        )
