from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from arta import IdentityError, OidcJwksAuthenticator
from arta.oidc_login import OidcAuthorizationCodeClient

ISSUER = "https://id.example.test/"
CLIENT_ID = "arta-web"


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _setup():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "login-key", "alg": "RS256", "use": "sig",
           "n": _b64u(public_numbers.n), "e": _b64u(public_numbers.e)}
    auth = OidcJwksAuthenticator(
        jwks_url="https://id.example.test/.well-known/jwks.json",
        issuer=ISSUER,
        audience=CLIENT_ID,
        fetcher=lambda _url, _timeout: json.dumps({"keys": [jwk]}).encode(),
    )
    return private, auth


def _id_token(private, nonce):
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-42",
                       "iat": now, "exp": now + 300, "scope": "openid profile",
                       "nonce": nonce, "jti": "login-test-token"},
                      private, algorithm="RS256", headers={"kid": "login-key"})


def _client(auth, exchange):
    return OidcAuthorizationCodeClient(
        authorization_endpoint="https://id.example.test/authorize",
        token_endpoint="https://id.example.test/token",
        client_id=CLIENT_ID,
        redirect_uri="https://app.example.test/oidc/callback",
        authenticator=auth,
        token_exchange=exchange,
    )


def test_pkce_login_builds_s256_request_and_validates_nonce():
    private, auth = _setup()
    seen = {}
    def exchange(url, fields, timeout):
        seen.update(fields)
        return json.dumps({"id_token": _id_token(private, seen["expected_nonce"]),
                           "access_token": "access-token-test",
                           "token_type": "Bearer", "expires_in": 600}).encode()

    client = _client(auth, lambda url, fields, timeout: exchange(url, {
        **fields,
        "expected_nonce": parse_qs(urlsplit(seen["authorization_url"]).query)["nonce"][0],
    }, timeout))
    start = client.begin_login()
    seen["authorization_url"] = start.authorization_url
    params = parse_qs(urlsplit(start.authorization_url).query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["state"] == [start.state]
    result = client.complete_login(code="authorization-code", state=start.state)
    assert result.principal.subject == "user-42"
    assert result.access_token == "access-token-test"
    expected = base64.urlsafe_b64encode(hashlib.sha256(seen["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert params["code_challenge"] == [expected]


def test_pkce_state_is_single_use_and_unknown_state_never_exchanges_code():
    _private, auth = _setup()
    calls = []
    client = _client(auth, lambda *_args: calls.append(True) or b"{}")
    start = client.begin_login()
    with pytest.raises(IdentityError, match="state"):
        client.complete_login(code="authorization-code", state="wrong-state")
    assert calls == []
    with pytest.raises(IdentityError, match="ID token"):
        client.complete_login(code="authorization-code", state=start.state)
    assert calls == [True]
    with pytest.raises(IdentityError, match="state"):
        client.complete_login(code="authorization-code", state=start.state)
    assert calls == [True]


def test_pkce_login_rejects_id_token_with_wrong_nonce():
    private, auth = _setup()
    client = _client(auth, lambda _url, _fields, _timeout: json.dumps({
        "id_token": _id_token(private, "different-nonce"),
        "access_token": "access-token-test", "token_type": "Bearer", "expires_in": 600,
    }).encode())
    start = client.begin_login()
    with pytest.raises(IdentityError, match="nonce"):
        client.complete_login(code="authorization-code", state=start.state)
    with pytest.raises(IdentityError, match="state"):
        client.complete_login(code="authorization-code", state=start.state)


@pytest.mark.parametrize("endpoint", [
    "http://id.example.test/token",
    "https://user:pass@id.example.test/token",
    "https://id.example.test/token?next=https://attacker.example",
])
def test_pkce_rejects_unsafe_token_endpoint(endpoint):
    _private, auth = _setup()
    with pytest.raises(IdentityError, match="HTTPS"):
        OidcAuthorizationCodeClient(
            authorization_endpoint="https://id.example.test/authorize",
            token_endpoint=endpoint,
            client_id=CLIENT_ID,
            redirect_uri="https://app.example.test/oidc/callback",
            authenticator=auth,
            token_exchange=lambda *_args: b"{}",
        )
