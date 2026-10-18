from __future__ import annotations

import json
import sqlite3

import pytest

from arta.core import (
    ApprovalStatus,
    AuthorityKernel,
    AuditEvent,
    Evidence,
    EvidenceOutcome,
    Mission,
    MissionError,
    MissionState,
    ToolGateway,
    ToolSpec,
    create_approval_record,
    fingerprint_action,
    verify_mission,
)
from arta.persistence import SQLiteMissionStore, StoreError, StoreIntegrityError
from arta.runner import MissionPlan, MissionRunner, PlannedAction


NOW = "2026-10-18T08:00:00+00:00"
ISSUED = "2026-10-18T07:00:00+00:00"
EXPIRES = "2026-10-18T09:00:00+00:00"


def completed_mission() -> Mission:
    item = Mission("Check a test report", ("report-read",))
    item.transition(MissionState.PLANNED)
    item.transition(MissionState.RUNNING)
    item.add_evidence(Evidence(
        criterion="report-read",
        outcome=EvidenceOutcome.PASS,
        source_action_id="read-1",
        summary="Synthetic fixture observation.",
        observed_at="2026-10-18T07:30:00+00:00",
        evidence_id="evidence-1",
    ))
    item.transition(MissionState.VERIFYING)
    assert verify_mission(item)
    return item


def approval_for_write() :
    return create_approval_record(
        "workspace.write",
        {"path": "reports/final.md", "content": "approved sample"},
        approver_id="trusted-test-operator",
        approved_at=ISSUED,
        expires_at=EXPIRES,
        approval_id="approval-write-1",
    )


def test_mission_and_hash_chained_audit_round_trip_across_store_reopen(tmp_path) -> None:
    path = tmp_path / "arta.sqlite3"
    item = completed_mission()
    expected_events = len(item.audit)

    with SQLiteMissionStore(path) as store:
        store.save_mission(item)
        store.save_mission(item)  # Idempotent snapshot save does not duplicate events.
        assert len(store.audit_events(item.mission_id)) == expected_events

    with SQLiteMissionStore(path) as reopened:
        loaded = reopened.load_mission(item.mission_id)
        assert loaded is not None
        assert loaded.goal == item.goal
        assert loaded.acceptance_criteria == item.acceptance_criteria
        assert loaded.state is MissionState.COMPLETED
        assert loaded.evidence == item.evidence
        assert loaded.audit == item.audit


def test_mission_audit_cannot_be_rewritten_and_changed_identity_is_rejected() -> None:
    item = completed_mission()
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        with pytest.raises(TypeError):
            item.audit[0] = AuditEvent("rewritten.created", item.mission_id)  # type: ignore[index]
        with pytest.raises(TypeError):
            item.audit[0].details["changed"] = True
        store.save_mission(item)

    original = completed_mission()
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(original)
        different = Mission("Different goal", original.acceptance_criteria, mission_id=original.mission_id)
        with pytest.raises(StoreError, match="identity is immutable"):
            store.save_mission(different)


def test_snapshot_checksum_detects_database_tampering() -> None:
    item = completed_mission()
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        row = store._connection.execute(
            "SELECT snapshot_json FROM missions WHERE mission_id=?", (item.mission_id,)
        ).fetchone()
        changed = row["snapshot_json"].replace("Check a test report", "Check a changed report")
        store._connection.execute(
            "UPDATE missions SET snapshot_json=? WHERE mission_id=?", (changed, item.mission_id)
        )
        with pytest.raises(StoreIntegrityError, match="snapshot hash mismatch"):
            store.load_mission(item.mission_id)


def test_database_triggers_reject_direct_mutation_of_audit_rows() -> None:
    item = completed_mission()
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._connection.execute(
                "UPDATE mission_audit_events SET event_json='{}' WHERE mission_id=? AND seq=1",
                (item.mission_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._connection.execute(
                "DELETE FROM mission_audit_events WHERE mission_id=? AND seq=1",
                (item.mission_id,),
            )


def test_approval_records_persist_and_revocation_is_audited() -> None:
    approval = approval_for_write()
    with SQLiteMissionStore(":memory:") as store:
        store.put_approval(approval)
        loaded = store.get_approval(approval.approval_id)
        assert loaded == approval
        revoked = store.revoke_approval(
            approval.approval_id,
            actor_id="trusted-test-operator",
            reason="User withdrew permission.",
        )
        assert revoked.status is ApprovalStatus.REVOKED
        assert store.get_approval(approval.approval_id).status is ApprovalStatus.REVOKED
        events = store._verify_chain_locked("approval_audit_events", "approval_id", approval.approval_id)
        assert len(events) == 2
        with pytest.raises(StoreError, match="Only an active approval"):
            store.revoke_approval(
                approval.approval_id,
                actor_id="trusted-test-operator",
                reason="Repeated revocation.",
            )


def test_duplicate_approval_ids_and_invalid_approval_records_are_rejected() -> None:
    approval = approval_for_write()
    with SQLiteMissionStore(":memory:") as store:
        store.put_approval(approval)
        with pytest.raises(StoreError, match="already exists"):
            store.put_approval(approval)
        forged = type(approval)(
            approval_id="bad-approval",
            approver_id="operator",
            action_fingerprint="not-a-hash",
            approved_at=ISSUED,
            expires_at=EXPIRES,
            status=ApprovalStatus.APPROVED,
        )
        with pytest.raises(StoreError, match="SHA-256"):
            store.put_approval(forged)


def test_action_journal_is_append_only_hashed_and_omits_raw_output() -> None:
    item = Mission("Read a test artifact", ("artifact-read",))
    fingerprint = fingerprint_action("artifact.read", {"path": "reports/final.md"})
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        store.record_action_event(item.mission_id, "read-1", "artifact.read", fingerprint, "prepared")
        store.record_action_event(item.mission_id, "read-1", "artifact.read", fingerprint, "started")
        unresolved = store.unresolved_actions(item.mission_id)
        assert len(unresolved) == 1
        assert unresolved[0]["status"] == "started"

        with pytest.raises(StoreError, match="Invalid action journal transition"):
            store.record_action_event(item.mission_id, "read-1", "artifact.read", fingerprint, "prepared")

        store.record_action_event(
            item.mission_id,
            "read-1",
            "artifact.read",
            fingerprint,
            "succeeded",
            result={"text": "very private sample output"},
        )
        rows = store.action_journal(item.mission_id)
        assert len(rows) == 1
        assert rows[0]["status"] == "succeeded"
        assert rows[0]["result_digest"] is not None
        assert "very private sample output" not in json.dumps(rows)
        assert store.unresolved_actions() == ()


def test_uncertain_actions_are_exposed_for_manual_recovery_not_retried() -> None:
    item = Mission("Publish a report", ("report-published",))
    fingerprint = fingerprint_action("report.publish", {"target": "reports/final.md"})
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        store.record_action_event(item.mission_id, "publish-1", "report.publish", fingerprint, "prepared")
        store.record_action_event(item.mission_id, "publish-1", "report.publish", fingerprint, "started")
        store.record_action_event(
            item.mission_id, "publish-1", "report.publish", fingerprint, "unknown",
            error_type="TimeoutError",
        )
        unresolved = store.unresolved_actions(item.mission_id)
        assert len(unresolved) == 1
        assert unresolved[0]["status"] == "unknown"
        assert unresolved[0]["error_type"] == "TimeoutError"


def test_runner_checkpoints_mission_and_action_status_durably() -> None:
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec(
        "report.read",
        lambda args: calls.append(args["path"]) or {"text": "synthetic response"},
        allowed_arguments=("path",),
        required_arguments=("path",),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    ))
    item = Mission("Read and validate a report", ("report-read",))
    plan = MissionPlan((
        PlannedAction("read-1", "report.read", "report-read", {"path": "reports/final.md"}),
    ))
    with SQLiteMissionStore(":memory:") as store:
        report = MissionRunner(gateway, store).run(
            item, plan, lambda action, result: (EvidenceOutcome.PASS, "Fixture check passed.")
        )
        assert report.completed
        assert calls == ["reports/final.md"]
        loaded = store.load_mission(item.mission_id)
        assert loaded is not None
        assert loaded.state is MissionState.COMPLETED
        assert any(event.event_type == "mission.verification_passed" for event in loaded.audit)
        journal = store.action_journal(item.mission_id)
        assert journal[0]["status"] == "succeeded"
        assert journal[0]["result_digest"] is not None
        assert store.unresolved_actions(item.mission_id) == ()


def test_runner_reads_revocation_from_store_instead_of_trusting_stale_plan() -> None:
    item = Mission("Write the approved report", ("report-written",))
    approval = approval_for_write()
    args = {"path": "reports/final.md", "content": "approved sample"}
    calls: list[str] = []
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec(
        "workspace.write",
        lambda payload: calls.append(payload["content"]) or {"written": True},
        read_only=False,
        allowed_arguments=("path", "content"),
        required_arguments=("path", "content"),
        target_argument="path",
        allowed_targets=("reports/final.md",),
    ))
    plan = MissionPlan((
        PlannedAction(
            "write-1", "workspace.write", "report-written", args, approval=approval
        ),
    ))
    with SQLiteMissionStore(":memory:") as store:
        store.put_approval(approval)
        store.revoke_approval(
            approval.approval_id, actor_id="trusted-test-operator", reason="Revoke before run."
        )
        report = MissionRunner(gateway, store).run(
            item, plan, lambda action, result: (EvidenceOutcome.PASS, "Write verified.")
        )
        assert report.state is MissionState.BLOCKED
        assert calls == []
        assert report.denied_action_ids == ("write-1",)


def test_runner_without_store_retains_existing_in_memory_behavior() -> None:
    item = Mission("Read a report", ("report-read",))
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW))
    gateway.register(ToolSpec("read", lambda args: {"ok": True}))
    report = MissionRunner(gateway).run(
        item,
        MissionPlan((PlannedAction("read-1", "read", "report-read"),)),
        lambda action, result: (EvidenceOutcome.PASS, "Read check passed."),
    )
    assert report.completed


def test_non_existing_mission_and_approval_loads_return_none() -> None:
    with SQLiteMissionStore(":memory:") as store:
        assert store.load_mission("missing-mission") is None
        assert store.get_approval("missing-approval") is None



def test_store_refuses_a_falsely_completed_mission() -> None:
    item = Mission("Claim completion without proof", ("report-read",))
    item.state = MissionState.COMPLETED  # Simulate unsafe direct field mutation.
    with SQLiteMissionStore(":memory:") as store:
        with pytest.raises(StoreError, match="passing evidence"):
            store.save_mission(item)


def test_store_refuses_completion_when_latest_evidence_is_failed() -> None:
    item = Mission("Attempt to bypass verifier", ("report-read",))
    item.state = MissionState.RUNNING
    item.add_evidence(Evidence(
        criterion="report-read",
        outcome=EvidenceOutcome.PASS,
        source_action_id="read-1",
        summary="Old passing observation.",
        observed_at="2026-10-18T07:00:00+00:00",
        evidence_id="evidence-pass",
    ))
    item.add_evidence(Evidence(
        criterion="report-read",
        outcome=EvidenceOutcome.FAIL,
        source_action_id="read-2",
        summary="Newer failed observation.",
        observed_at="2026-10-18T07:30:00+00:00",
        evidence_id="evidence-fail",
    ))
    item.state = MissionState.COMPLETED
    with SQLiteMissionStore(":memory:") as store:
        with pytest.raises(StoreError, match="latest evidence"):
            store.save_mission(item)


def test_action_journal_detects_projection_tampering() -> None:
    item = Mission("Track a tool action", ("tracked",))
    fingerprint = fingerprint_action("read", {"path": "reports/final.md"})
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        store.record_action_event(item.mission_id, "read-1", "read", fingerprint, "prepared")
        store.record_action_event(item.mission_id, "read-1", "read", fingerprint, "started")
        store._connection.execute(
            "UPDATE action_journal SET status='succeeded' WHERE mission_id=? AND action_id=?",
            (item.mission_id, "read-1"),
        )
        with pytest.raises(StoreIntegrityError, match="projection mismatch|state mismatch"):
            store.action_journal(item.mission_id)


def test_revoked_approval_projection_cannot_be_reverted_without_detection() -> None:
    approval = approval_for_write()
    with SQLiteMissionStore(":memory:") as store:
        store.put_approval(approval)
        store.revoke_approval(
            approval.approval_id, actor_id="trusted-test-operator", reason="Revoke it."
        )
        store._connection.execute(
            "UPDATE approvals SET status='approved' WHERE approval_id=?",
            (approval.approval_id,),
        )
        with pytest.raises(StoreIntegrityError, match="status does not match"):
            store.get_approval(approval.approval_id)



def test_hash_chain_detects_corrupted_hash_even_if_sql_trigger_is_removed() -> None:
    item = completed_mission()
    with SQLiteMissionStore(":memory:") as store:
        store.save_mission(item)
        store._connection.execute("DROP TRIGGER mission_audit_no_update")
        store._connection.execute(
            "UPDATE mission_audit_events SET event_hash=? WHERE mission_id=? AND seq=1",
            ("not-a-valid-digest", item.mission_id),
        )
        with pytest.raises(StoreIntegrityError, match="hash mismatch"):
            store.audit_events(item.mission_id)
