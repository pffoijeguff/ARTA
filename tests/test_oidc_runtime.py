from __future__ import annotations

from arta import BubblewrapSandbox, HmacApprovalAuthority, OidcJwksAuthenticator, SecureRuntime, SQLiteMissionStore


def test_oidc_jwks_authenticator_can_be_composed_into_secure_runtime(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    bwrap = tmp_path / "bwrap"
    bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    bwrap.chmod(0o755)
    authenticator = OidcJwksAuthenticator(
        jwks_url="https://identity.example.test/.well-known/jwks.json",
        issuer="https://identity.example.test",
        audience="arta-runtime",
        fetcher=lambda _url, _timeout: b'{"keys": []}',
    )
    runtime = SecureRuntime(
        authenticator=authenticator,
        approval_authority=HmacApprovalAuthority(b"test-hmac-key-material-long-enough-32bytes"),
        store=SQLiteMissionStore(tmp_path / "missions.sqlite3"),
        sandbox=BubblewrapSandbox(workspace, allowed_executables={"python": "/usr/bin/true"},
                                  bwrap_path=bwrap),
        required_scopes_by_tool={"sandbox.run": ()},
    )
    assert runtime.tool_name == "sandbox.run"
