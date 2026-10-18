"""Provider-agnostic OIDC JWKS loading with bounded cache and safe key rotation.

The JWKS endpoint is trusted operator configuration, never taken from token headers or claims.
This module verifies identity tokens only; it does not implement an interactive login flow.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
except ImportError:  # pragma: no cover - installation misconfiguration
    jwt = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]

from .identity import (
    AuthenticatedPrincipal,
    IdentityError,
    JwtPrincipalAuthenticator,
    _SUPPORTED_ASYMMETRIC_ALGORITHMS,
)

_MAX_JWKS_BYTES = 1_048_576
_MAX_JWKS_KEYS = 100
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _fetch_https_jwks(url: str, timeout_seconds: float) -> bytes:
    request = Request(url, headers={"Accept": "application/jwk-set+json, application/json",
                                    "User-Agent": "ARTA-OIDC-JWKS/1"})
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            if response.geturl() != url:
                raise IdentityError("JWKS endpoint redirects are not permitted.")
            content_type = response.headers.get_content_type()
            if content_type not in {"application/json", "application/jwk-set+json"}:
                raise IdentityError("JWKS endpoint returned an unsupported content type.")
            payload = response.read(_MAX_JWKS_BYTES + 1)
    except HTTPError as exc:
        raise IdentityError(f"JWKS endpoint returned HTTP {exc.code}.") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise IdentityError("JWKS endpoint could not be reached securely.") from None
    if len(payload) > _MAX_JWKS_BYTES:
        raise IdentityError("JWKS document exceeds the configured size limit.")
    return payload


@dataclass(frozen=True)
class _KeySet:
    keys_by_kid: dict[str, tuple[str, str]]
    expires_at: float


class OidcJwksAuthenticator:
    """Authenticate JWTs using a fixed HTTPS JWKS endpoint and a bounded cache.

    Unknown key IDs trigger one forced refresh, allowing normal provider key rotation.
    Redirects, non-HTTPS endpoints, token-selected key URLs, symmetric algorithms,
    duplicate key IDs, private JWK material, and oversized key sets are rejected.
    """

    def __init__(
        self,
        *,
        jwks_url: str,
        issuer: str,
        audience: str,
        cache_ttl_seconds: int = 300,
        timeout_seconds: float = 3.0,
        max_token_lifetime_seconds: int = 3600,
        leeway_seconds: int = 0,
        scope_claim: str = "scope",
        fetcher: Callable[[str, float], bytes] | None = None,
    ) -> None:
        if jwt is None or serialization is None:
            raise IdentityError("PyJWT[crypto] is required for OIDC JWKS authentication.")
        parsed = urlsplit(jwks_url) if isinstance(jwks_url, str) else None
        if (parsed is None or parsed.scheme.lower() != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment):
            raise IdentityError("JWKS URL must be a fixed HTTPS URL without userinfo or fragment.")
        if not isinstance(issuer, str) or not issuer.startswith("https://"):
            raise IdentityError("OIDC issuer must be a fixed HTTPS issuer.")
        if (isinstance(cache_ttl_seconds, bool) or not isinstance(cache_ttl_seconds, int)
                or not 1 <= cache_ttl_seconds <= 3600):
            raise IdentityError("JWKS cache TTL must be between 1 and 3600 seconds.")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0.1 <= timeout_seconds <= 10):
            raise IdentityError("JWKS request timeout must be between 0.1 and 10 seconds.")
        self._url = jwks_url
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = cache_ttl_seconds
        self._timeout = float(timeout_seconds)
        self._max_lifetime = max_token_lifetime_seconds
        self._leeway = leeway_seconds
        self._scope_claim = scope_claim
        self._fetcher = fetcher or _fetch_https_jwks
        self._cache: _KeySet | None = None
        self._lock = threading.RLock()

    def _load_keys(self) -> dict[str, tuple[str, str]]:
        try:
            raw = self._fetcher(self._url, self._timeout)
            if not isinstance(raw, bytes) or len(raw) > _MAX_JWKS_BYTES:
                raise IdentityError("JWKS fetcher returned invalid or oversized content.")
            document = json.loads(raw.decode("utf-8"))
        except IdentityError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise IdentityError("JWKS document is not valid UTF-8 JSON.") from None
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise IdentityError("JWKS document must contain a keys array.")
        if not 1 <= len(document["keys"]) <= _MAX_JWKS_KEYS:
            raise IdentityError("JWKS key count is outside the allowed range.")

        keys: dict[str, tuple[str, str]] = {}
        seen_kids: set[str] = set()
        for jwk_data in document["keys"]:
            if not isinstance(jwk_data, dict):
                raise IdentityError("JWKS contains a malformed key.")
            kid = jwk_data.get("kid")
            alg = jwk_data.get("alg")
            if not isinstance(kid, str) or not kid or kid != kid.strip() or kid in seen_kids:
                raise IdentityError("JWKS key IDs must be unique, non-empty, trimmed strings.")
            seen_kids.add(kid)
            if not isinstance(alg, str) or alg not in _SUPPORTED_ASYMMETRIC_ALGORITHMS:
                raise IdentityError("JWKS keys must declare a supported asymmetric algorithm.")
            if _PRIVATE_JWK_FIELDS.intersection(jwk_data):
                raise IdentityError("JWKS must not expose private key material.")
            if jwk_data.get("use", "sig") != "sig":
                continue
            key_ops = jwk_data.get("key_ops")
            if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
                continue
            try:
                parsed_key = jwt.PyJWK.from_dict(jwk_data, algorithm=alg)
                public_key = parsed_key.key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
            except Exception:
                raise IdentityError("JWKS contains a key that cannot be used for signature verification.") from None
            keys[kid] = (alg, public_key)
        if not keys:
            raise IdentityError("JWKS contains no eligible signature-verification keys.")
        return keys

    def _keys(self, *, force_refresh: bool = False) -> dict[str, tuple[str, str]]:
        with self._lock:
            now = time.monotonic()
            if not force_refresh and self._cache is not None and now < self._cache.expires_at:
                return self._cache.keys_by_kid
            keys = self._load_keys()
            self._cache = _KeySet(keys, time.monotonic() + self._cache_ttl)
            return keys

    def authenticate(self, bearer_token: str) -> AuthenticatedPrincipal:
        if not isinstance(bearer_token, str) or not bearer_token.strip():
            raise IdentityError("A bearer token is required.")
        token = bearer_token.strip()
        if token[:7].lower() == "bearer ":
            token = token[7:].strip()
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            raise IdentityError("Bearer token is not a valid JWT.") from None
        kid, alg = header.get("kid"), header.get("alg")
        if (not isinstance(kid, str) or not kid or not isinstance(alg, str)
                or alg not in _SUPPORTED_ASYMMETRIC_ALGORITHMS):
            raise IdentityError("JWT must declare a supported asymmetric algorithm and key ID.")

        keys = self._keys()
        if kid not in keys:
            keys = self._keys(force_refresh=True)
        configured = keys.get(kid)
        if configured is None or configured[0] != alg:
            raise IdentityError("JWT key ID or algorithm is not trusted by the configured issuer.")
        verifier = JwtPrincipalAuthenticator(
            keys_by_kid=keys,
            issuer=self._issuer,
            audience=self._audience,
            scope_claim=self._scope_claim,
            max_token_lifetime_seconds=self._max_lifetime,
            leeway_seconds=self._leeway,
        )
        return verifier.authenticate(token)
