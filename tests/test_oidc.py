from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from arta.identity import IdentityError
from arta.oidc import OidcJwksAuthenticator

ISSUER = "https://id.example.test/"
AUDIENCE = "arta-test"


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _key_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "key-1", "alg": "RS256", "use": "sig",
           "key_ops": ["verify"], "n": _b64u(numbers.n), "e": _b64u(numbers.e)}
    return private, jwk


def _token(private, kid="key-1"):
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "operator-1",
                       "iat": now, "exp": now + 120, "scope": "arta:approve",
                       "jti": "oidc-test-token"},
                      private, algorithm="RS256", headers={"kid": kid})


def _document(*keys):
    return json.dumps({"keys": list(keys)}).encode("utf-8")


def _auth(fetcher, **kwargs):
    return OidcJwksAuthenticator(jwks_url="https://id.example.test/.well-known/jwks.json",
        issuer=ISSUER, audience=AUDIENCE, fetcher=fetcher, **kwargs)


def test_jwks_authenticates_token_and_caches_keys():
    private, jwk = _key_pair()
    calls = []
    auth = _auth(lambda url, timeout: calls.append((url, timeout)) or _document(jwk))
    principal = auth.authenticate("Bearer " + _token(private))
    assert principal.subject == "operator-1"
    assert "arta:approve" in principal.scopes
    auth.authenticate(_token(private))
    assert len(calls) == 1


def test_unknown_kid_forces_one_refresh_for_rotation():
    first_private, first_jwk = _key_pair()
    second_private, second_jwk = _key_pair()
    second_jwk = {**second_jwk, "kid": "key-2"}
    documents = [_document(first_jwk), _document(first_jwk, second_jwk)]
    calls = []
    def fetcher(url, timeout):
        calls.append(url)
        return documents.pop(0)
    auth = _auth(fetcher)
    assert auth.authenticate(_token(first_private)).subject == "operator-1"
    assert auth.authenticate(_token(second_private, kid="key-2")).subject == "operator-1"
    assert len(calls) == 2


@pytest.mark.parametrize("url", [
    "http://id.example.test/jwks",
    "https://user:password@id.example.test/jwks",
    "https://id.example.test/jwks#fragment",
])
def test_unsafe_jwks_urls_are_rejected(url):
    with pytest.raises(IdentityError, match="HTTPS"):
        OidcJwksAuthenticator(jwks_url=url, issuer=ISSUER, audience=AUDIENCE,
                              fetcher=lambda _url, _timeout: b'{"keys": []}')


def test_unknown_kid_after_refresh_is_rejected():
    private, jwk = _key_pair()
    auth = _auth(lambda _url, _timeout: _document(jwk))
    with pytest.raises(IdentityError, match="key ID"):
        auth.authenticate(_token(private, kid="not-published"))


def test_private_jwk_material_is_rejected():
    _private, jwk = _key_pair()
    with pytest.raises(IdentityError, match="private"):
        _auth(lambda _url, _timeout: _document({**jwk, "d": "must-not-appear"})).authenticate("not-a-token")


def test_malformed_jwks_is_rejected():
    auth = _auth(lambda _url, _timeout: b'{"keys": "not-an-array"}')
    with pytest.raises(IdentityError, match="keys array"):
        auth.authenticate("not-a-token")


def test_token_selected_algorithm_is_not_trusted():
    private, jwk = _key_pair()
    auth = _auth(lambda _url, _timeout: _document(jwk))
    forged = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "attacker"},
                        "attacker-controlled-secret", algorithm="HS256", headers={"kid": "key-1"})
    with pytest.raises(IdentityError, match="asymmetric"):
        auth.authenticate(forged)
