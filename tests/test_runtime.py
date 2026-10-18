from __future__ import annotations
import sys
from datetime import datetime, timezone
from pathlib import Path
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from arta import (BubblewrapSandbox, EvidenceOutcome, HmacApprovalAuthority, IdentityError,
                  JwtPrincipalAuthenticator, Mission, MissionPlan, MissionState, PlannedAction,
                  SecureRuntime, SQLiteMissionStore, SandboxResult)
from arta.core import MissionError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="SecureRuntime requires Linux Bubblewrap.")
ISSUER = "https://identity.example.test"
AUDIENCE = "arta-runtime"
APPROVAL_KEY = b"secure-runtime-test-hmac-key-material-32bytes"

def _keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public

def _token(private, scope="arta:approve arta:approve:sandbox.run", subject="operator-7"):
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": subject, "iat": now,
        "exp": now + 300, "scope": scope, "jti": "secure-runtime-test-token"},
        private, algorithm="RS256", headers={"kid": "runtime-test-key"})

def _sandbox(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "project"
    workspace.mkdir()
    fake_bwrap = tmp_path / "bwrap"
    fake_bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_bwrap.chmod(0o755)
    sandbox = BubblewrapSandbox(workspace, allowed_executables={"python": "/usr/bin/true"},
                                bwrap_path=fake_bwrap)
    calls = []
    def fake_run(executable, arguments=(), *, timeout_seconds=None):
        calls.append((executable, tuple(arguments), timeout_seconds))
        return SandboxResult(executable, 0, "ok", "", False, False, False, 0.01)
    monkeypatch.setattr(sandbox, "run", fake_run)
    return sandbox, calls

def _runtime(tmp_path, monkeypatch):
    private, public = _keys()
    auth = JwtPrincipalAuthenticator(keys_by_kid={"runtime-test-key": ("RS256", public)},
                                     issuer=ISSUER, audience=AUDIENCE)
    authority = HmacApprovalAuthority(APPROVAL_KEY)
    store = SQLiteMissionStore(tmp_path / "runtime.sqlite3")
    sandbox, calls = _sandbox(tmp_path, monkeypatch)
    runtime = SecureRuntime(authenticator=auth, approval_authority=authority, store=store,
        sandbox=sandbox, required_scopes_by_tool={"sandbox.run": ()})
    return runtime, store, calls, private, authority

def _mission_plan(arguments, approval):
    mission = Mission("Run reviewed sandbox command", ("command-exit-zero",))
    action = PlannedAction("action-1", "sandbox.run", "command-exit-zero",
                           arguments=arguments, approval=approval)
    return mission, MissionPlan((action,))

def _verify(_action, _result):
    return EvidenceOutcome.PASS, "Exit status and bounded result checked by test verifier."

def test_secure_runtime_composes_identity_approval_store_and_sandbox(tmp_path, monkeypatch):
    runtime, store, calls, private, authority = _runtime(tmp_path, monkeypatch)
    args = {"executable": "python", "arguments": ["-I", "-c", "print('ok')"]}
    approval = runtime.issue_approval(_token(private), args, lifetime_seconds=60)
    assert authority.verify(approval)
    assert store.get_approval(approval.approval_id) == approval
    mission, plan = _mission_plan(args, approval)
    report = runtime.run(mission, plan, _verify)
    assert report.completed and report.state is MissionState.COMPLETED
    assert calls == [("python", ("-I", "-c", "print('ok')"), None)]

def test_missing_scope_is_rejected_before_side_effect(tmp_path, monkeypatch):
    runtime, store, calls, private, _authority = _runtime(tmp_path, monkeypatch)
    with pytest.raises(IdentityError, match="scope"):
        runtime.issue_approval(_token(private, scope="arta:approve"),
                               {"executable": "python", "arguments": []})
    assert calls == []
    assert store.get_approval("not-created") is None

def test_approval_is_bound_to_exact_arguments(tmp_path, monkeypatch):
    runtime, _store, calls, private, _authority = _runtime(tmp_path, monkeypatch)
    approved = {"executable": "python", "arguments": ["-c", "print('approved')"]}
    approval = runtime.issue_approval(_token(private), approved)
    mission, plan = _mission_plan({"executable": "python", "arguments": ["-c", "print('changed')"]}, approval)
    report = runtime.run(mission, plan, _verify)
    assert not report.completed
    assert report.state in {MissionState.BLOCKED, MissionState.FAILED}
    assert calls == []

def test_consumed_approval_cannot_be_replayed_across_missions(tmp_path, monkeypatch):
    runtime, _store, calls, private, _authority = _runtime(tmp_path, monkeypatch)
    args = {"executable": "python", "arguments": ["-c", "print('once')"]}
    approval = runtime.issue_approval(_token(private), args)
    first_mission, first_plan = _mission_plan(args, approval)
    assert runtime.run(first_mission, first_plan, _verify).completed
    second_mission, second_plan = _mission_plan(args, approval)
    second = runtime.run(second_mission, second_plan, _verify)
    assert not second.completed and second.state is MissionState.BLOCKED
    assert calls == [("python", ("-c", "print('once')"), None)]

def test_runtime_rejects_plans_outside_its_sandbox_tool(tmp_path, monkeypatch):
    runtime, _store, calls, _private, _authority = _runtime(tmp_path, monkeypatch)
    mission = Mission("Attempt unregistered action", ("criterion",))
    plan = MissionPlan((PlannedAction("action-1", "workspace.write", "criterion",
                                      {"path": "x"}),))
    with pytest.raises(MissionError, match="outside its sandbox boundary"):
        runtime.run(mission, plan, _verify)
    assert calls == []
