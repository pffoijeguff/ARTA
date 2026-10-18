from __future__ import annotations

from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from arta.approvals import HmacApprovalAuthority
from arta.core import AuthorityKernel, ToolSpec
from arta.identity import IdentityError, JwtPrincipalAuthenticator, TrustedApprovalService
from arta.persistence import SQLiteMissionStore


ISSUER = "https://identity.example.test"
AUDIENCE = "arta-runtime"
APPROVAL_KEY = b"arta-identity-tests-approval-hmac-key"


@pytest.fixture()
def signing_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, public_pem, other_private


def make_token(
    private_key,
    *,
    kid: str = "trusted-test-key",
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    scope: str = "arta:approve arta:approve:workspace.write",
    lifetime_seconds: int = 300,
    subject: str = "user-42",
    omit: tuple[str, ...] = (),
    algorithm: str = "RS256",
) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": now,
        "exp": now + lifetime_seconds,
        "scope": scope,
        "jti": "test-token-unique-id",
    }
    for claim in omit:
        claims.pop(claim, None)
    signing_key = b"attacker-controlled-hs256-test-secret" if algorithm == "HS256" else private_key
    return jwt.encode(claims, signing_key, algorithm=algorithm, headers={"kid": kid})


def make_authenticator(public_pem: bytes) -> JwtPrincipalAuthenticator:
    return JwtPrincipalAuthenticator(
        keys_by_kid={"trusted-test-key": ("RS256", public_pem)},
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def test_jwt_authenticator_returns_identity_only_after_signature_and_claim_validation(signing_keys) -> None:
    private, public_pem, _ = signing_keys
    authenticator = make_authenticator(public_pem)
    principal = authenticator.authenticate(
        "Bearer " + make_token(private, subject="identity-provider|user-42")
    )

    assert principal.subject == "identity-provider|user-42"
    assert principal.issuer == ISSUER
    assert principal.audience == AUDIENCE
    assert "arta:approve" in principal.scopes
    assert "arta:approve:workspace.write" in principal.scopes
    assert principal.expires_at > principal.issued_at


@pytest.mark.parametrize(
    "kwargs",
    [
        {"kid": "unknown-key"},
        {"issuer": "https://attacker.example.test"},
        {"audience": "different-application"},
        {"lifetime_seconds": -10},
        {"omit": ("exp",)},
        {"omit": ("sub",)},
        {"omit": ("scope",)},
    ],
)
def test_jwt_claim_or_key_failures_are_rejected(signing_keys, kwargs) -> None:
    private, public_pem, _ = signing_keys
    token = make_token(private, **kwargs)
    with pytest.raises(IdentityError):
        make_authenticator(public_pem).authenticate(token)


def test_invalid_signature_and_algorithm_confusion_are_rejected(signing_keys) -> None:
    private, public_pem, other_private = signing_keys
    authenticator = make_authenticator(public_pem)
    forged = make_token(other_private)
    with pytest.raises(IdentityError):
        authenticator.authenticate(forged)

    algorithm_mismatch = make_token(
        private,
        algorithm="HS256",
    )
    with pytest.raises(IdentityError):
        authenticator.authenticate(algorithm_mismatch)


def test_lifetime_beyond_configured_maximum_is_rejected(signing_keys) -> None:
    private, public_pem, _ = signing_keys
    token = make_token(private, lifetime_seconds=7200)
    authenticator = JwtPrincipalAuthenticator(
        keys_by_kid={"trusted-test-key": ("RS256", public_pem)},
        issuer=ISSUER,
        audience=AUDIENCE,
        max_token_lifetime_seconds=3600,
    )
    with pytest.raises(IdentityError, match="maximum"):
        authenticator.authenticate(token)


def test_trusted_approval_service_authenticates_scope_signs_and_persists(signing_keys) -> None:
    private, public_pem, _ = signing_keys
    authenticator = make_authenticator(public_pem)
    authority = HmacApprovalAuthority(APPROVAL_KEY)
    with SQLiteMissionStore(":memory:") as store:
        service = TrustedApprovalService(
            authenticator=authenticator,
            authority=authority,
            store=store,
            required_scopes_by_tool={"workspace.write": ()},
        )
        token = make_token(private, subject="trusted-subject-9")
        approval = service.issue_approval(
            token,
            "workspace.write",
            {"path": "reports/final.md", "content": "reviewed"},
            lifetime_seconds=60,
        )
        assert approval.approver_id == "trusted-subject-9"
        assert authority.verify(approval)
        persisted = store.get_approval(approval.approval_id)
        assert persisted == approval
        assert authority.verify(persisted)
        kernel = AuthorityKernel(approval_verifier=authority.verify)
        assert kernel.decide(
            # Test the signed approval record is usable only under a configured authority.
            ToolSpec(
                "workspace.write",
                lambda _args: {"ok": True},
                read_only=False,
                allowed_arguments=("path", "content"),
                required_arguments=("path", "content"),
                target_argument="path",
                allowed_targets=("reports/final.md",),
            ),
            arguments={"path": "reports/final.md", "content": "reviewed"},
            approval=persisted,
        ).effect.value == "allow"


def test_approval_service_rejects_missing_scope_unregistered_tool_and_excessive_lifetime(signing_keys) -> None:
    private, public_pem, _ = signing_keys
    authenticator = make_authenticator(public_pem)
    authority = HmacApprovalAuthority(APPROVAL_KEY)
    with SQLiteMissionStore(":memory:") as store:
        service = TrustedApprovalService(
            authenticator=authenticator,
            authority=authority,
            store=store,
            required_scopes_by_tool={"workspace.write": ()},
            max_approval_lifetime_seconds=90,
        )
        no_tool_scope = make_token(private, scope="arta:approve")
        with pytest.raises(IdentityError, match="scope"):
            service.issue_approval(no_tool_scope, "workspace.write", {"path": "report.md", "content": "x"}, lifetime_seconds=60)
        with pytest.raises(IdentityError, match="not configured"):
            service.issue_approval(make_token(private), "unregistered.tool", {}, lifetime_seconds=60)
        with pytest.raises(IdentityError, match="lifetime"):
            service.issue_approval(make_token(private), "workspace.write", {}, lifetime_seconds=91)
        assert store.get_approval("not-created") is None


def test_token_cannot_choose_an_untrusted_key(signing_keys) -> None:
    private, public_pem, _ = signing_keys
    token = make_token(private)
    configured = JwtPrincipalAuthenticator(
        keys_by_kid={"different-key-id": ("RS256", public_pem)},
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    with pytest.raises(IdentityError, match="key"):
        configured.authenticate(token)
