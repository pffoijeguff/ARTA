from __future__ import annotations

import hashlib
import os

import pytest

from arta.approvals import HmacApprovalAuthority
from arta.core import (
    AuthorityKernel,
    EvidenceOutcome,
    Mission,
    MissionState,
    PolicyEffect,
    ToolGateway,
)
from arta.runner import MissionPlan, MissionRunner, PlannedAction
from arta.workspace import WorkspaceAdapter, WorkspaceError


NOW = "2026-10-18T08:00:00+00:00"
ISSUED = "2026-10-18T07:00:00+00:00"
EXPIRES = "2026-10-18T09:00:00+00:00"


def test_read_and_create_return_content_and_integrity_metadata(tmp_path) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("reports/final.md",))
    (tmp_path / "reports").mkdir()
    written = adapter.write({"path": "reports/final.md", "content": "# ARTA\n"})
    read = adapter.read({"path": "reports/final.md"})

    assert written["created"] is True
    assert written["before_sha256"] is None
    assert written["after_sha256"] == hashlib.sha256(b"# ARTA\n").hexdigest()
    assert read == {
        "path": "reports/final.md",
        "content": "# ARTA\n",
        "sha256": written["after_sha256"],
        "bytes": 7,
    }
    assert (tmp_path / "reports" / "final.md").read_text(encoding="utf-8") == "# ARTA\n"


def test_existing_file_requires_exact_expected_hash_and_rejects_stale_write(tmp_path) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("report.md",))
    target = tmp_path / "report.md"
    target.write_text("version one", encoding="utf-8")
    before = adapter.read({"path": "report.md"})

    with pytest.raises(WorkspaceError, match="expected_sha256"):
        adapter.write({"path": "report.md", "content": "version two"})
    with pytest.raises(WorkspaceError, match="expected_sha256"):
        adapter.write({
            "path": "report.md", "content": "version two", "expected_sha256": "0" * 64
        })

    result = adapter.write({
        "path": "report.md",
        "content": "version two",
        "expected_sha256": before["sha256"],
    })
    assert result["created"] is False
    assert result["before_sha256"] == before["sha256"]
    assert adapter.read({"path": "report.md"})["content"] == "version two"


def test_paths_must_be_normalized_and_explicitly_allowlisted(tmp_path) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("report.md",))
    for path in ("../secret.txt", "/etc/passwd", "folder/../secret", "report\\secret.md", ""):
        with pytest.raises(WorkspaceError):
            adapter.read({"path": path})
    with pytest.raises(WorkspaceError, match="allowlist"):
        adapter.read({"path": "another.md"})


def test_symlink_targets_and_symlinked_parent_directories_are_rejected(tmp_path) -> None:
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.md").write_text("not for ARTA", encoding="utf-8")
    (root / "linked.md").symlink_to(outside / "secret.md")
    (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    adapter = WorkspaceAdapter(
        root, allowed_paths=("linked.md", "linked-dir/secret.md")
    )

    with pytest.raises(WorkspaceError, match="Symlinks"):
        adapter.read({"path": "linked.md"})
    with pytest.raises(WorkspaceError, match="Symlinks"):
        adapter.read({"path": "linked-dir/secret.md"})
    assert (outside / "secret.md").read_text(encoding="utf-8") == "not for ARTA"


def test_binary_and_oversized_files_are_rejected(tmp_path) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("binary.dat", "large.txt"), max_file_bytes=16)
    (tmp_path / "binary.dat").write_bytes(b"\xff\xfe")
    (tmp_path / "large.txt").write_bytes(b"x" * 17)

    with pytest.raises(WorkspaceError, match="UTF-8"):
        adapter.read({"path": "binary.dat"})
    with pytest.raises(WorkspaceError, match="size limit"):
        adapter.read({"path": "large.txt"})
    with pytest.raises(WorkspaceError, match="size limit"):
        adapter.write({"path": "large.txt", "content": "x" * 17})


def test_directory_target_and_invalid_write_payloads_are_rejected(tmp_path) -> None:
    (tmp_path / "directory").mkdir()
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("directory", "report.md"))
    with pytest.raises(WorkspaceError, match="regular files"):
        adapter.write({"path": "directory", "content": "no"})
    with pytest.raises(WorkspaceError, match="UTF-8 string"):
        adapter.write({"path": "report.md", "content": 123})
    with pytest.raises(WorkspaceError, match="NUL"):
        adapter.write({"path": "report.md", "content": "bad\x00content"})
    with pytest.raises(WorkspaceError, match="expected_sha256"):
        adapter.write({"path": "report.md", "content": "text", "expected_sha256": "bad"})


def test_atomic_write_failure_keeps_original_file_and_cleans_temp_file(tmp_path, monkeypatch) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("report.md",))
    target = tmp_path / "report.md"
    target.write_text("stable", encoding="utf-8")
    expected = adapter.read({"path": "report.md"})["sha256"]

    def fail_replace(source, destination):
        raise OSError("private operating-system detail")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(WorkspaceError, match="write failed"):
        adapter.write({
            "path": "report.md", "content": "changed", "expected_sha256": expected
        })
    assert target.read_text(encoding="utf-8") == "stable"
    assert not list(tmp_path.glob(".arta-write-*"))


def test_registered_write_tool_requires_an_action_bound_signed_approval(tmp_path) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("report.md",))
    gateway = ToolGateway(AuthorityKernel(
        clock=lambda: NOW,
        approval_verifier=HmacApprovalAuthority(b"k" * 32).verify,
    ))
    adapter.register(gateway)
    mission = Mission("Create the approved report", ("report-created",))
    args = {"path": "report.md", "content": "approved content"}
    plan_without_approval = MissionPlan((
        PlannedAction("write-1", "workspace.write", "report-created", args),
    ))
    blocked = MissionRunner(gateway).run(
        mission, plan_without_approval,
        lambda action, result: (EvidenceOutcome.PASS, "Write observed."),
    )
    assert blocked.state is MissionState.AWAITING_APPROVAL
    assert not (tmp_path / "report.md").exists()

    signer = HmacApprovalAuthority(b"k" * 32)
    approval = signer.issue(
        "workspace.write", args, approver_id="authenticated-test-user",
        approved_at=ISSUED, expires_at=EXPIRES, approval_id="approval-write",
    )
    approved_mission = Mission("Create the approved report", ("report-created",))
    approved_plan = MissionPlan((
        PlannedAction("write-2", "workspace.write", "report-created", args, approval=approval),
    ))
    report = MissionRunner(gateway).run(
        approved_mission, approved_plan,
        lambda action, result: (
            EvidenceOutcome.PASS
            if result.output["after_sha256"] == hashlib.sha256(b"approved content").hexdigest()
            else EvidenceOutcome.FAIL,
            "Observed output hash matches the expected file state.",
        ),
    )
    assert report.completed is True
    assert (tmp_path / "report.md").read_text(encoding="utf-8") == "approved content"


def test_signed_approval_cannot_be_replayed_for_changed_file_content(tmp_path) -> None:
    signer = HmacApprovalAuthority(b"z" * 32)
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("report.md",))
    gateway = ToolGateway(AuthorityKernel(clock=lambda: NOW, approval_verifier=signer.verify))
    adapter.register(gateway)
    original_args = {"path": "report.md", "content": "approved"}
    approval = signer.issue(
        "workspace.write", original_args, approver_id="authenticated-test-user",
        approved_at=ISSUED, expires_at=EXPIRES, approval_id="approval-exact",
    )
    changed_args = {"path": "report.md", "content": "changed"}
    mission = Mission("Attempt a changed write", ("report-created",))
    report = MissionRunner(gateway).run(
        mission,
        MissionPlan((
            PlannedAction("write-1", "workspace.write", "report-created", changed_args, approval=approval),
        )),
        lambda action, result: (EvidenceOutcome.PASS, "Should not be reached."),
    )
    assert report.state is MissionState.BLOCKED
    assert not (tmp_path / "report.md").exists()


def test_workspace_register_rejects_invalid_gateway(tmp_path) -> None:
    adapter = WorkspaceAdapter(tmp_path, allowed_paths=("report.md",))
    with pytest.raises(WorkspaceError, match="ToolGateway"):
        adapter.register(object())  # type: ignore[arg-type]
