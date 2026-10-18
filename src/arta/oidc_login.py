"""Public-client OIDC Authorization Code + PKCE flow primitives.

This module is an identity-provider client, not an HTTP server or session store. The host
application must bind callbacks to the configured redirect URI, protect browser state/cookies,
and create its own authenticated session only after complete_login succeeds.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .identity import AuthenticatedPrincipal, IdentityError
from .oidc import OidcJwksAuthenticator
from .pending_login_store import InMemoryPendingLoginStore, PendingLoginStore

_MAX_TOKEN_RESPONSE_BYTES = 65_536
_MAX_AUTH_CODE_CHARS = 4096


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _validate_https_endpoint(value: str, label: str) -> None:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (parsed is None or parsed.scheme.lower() != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.query):
        raise IdentityError(f"{label} must be a fixed HTTPS URL without userinfo, query, or fragment.")


def _post_token_form(url: str, fields: Mapping[str, str], timeout_seconds: float) -> bytes:
    body = urlencode(fields).encode("ascii")
    request = Request(url, data=body, method="POST", headers={
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "ARTA-OIDC-PKCE/1",
    })
    try:
        with build_opener(_NoRedirect()).open(request, timeout=timeout_seconds) as response:
            if response.geturl() != url:
                raise IdentityError("OIDC token endpoint redirects are not permitted.")
            if response.headers.get_content_type() != "application/json":
                raise IdentityError("OIDC token endpoint returned an unsupported content type.")
            payload = response.read(_MAX_TOKEN_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise IdentityError(f"OIDC token endpoint returned HTTP {exc.code}.") from None
    except (URLError, TimeoutError, OSError):
        raise IdentityError("OIDC token endpoint could not be reached securely.") from None
    if len(payload) > _MAX_TOKEN_RESPONSE_BYTES:
        raise IdentityError("OIDC token response exceeds the configured size limit.")
    return payload


@dataclass(frozen=True)
class LoginStart:
    authorization_url: str
    state: str
    expires_in_seconds: int


@dataclass(frozen=True)
class OidcLoginResult:
    principal: AuthenticatedPrincipal
    access_token: str = field(repr=False)
    expires_in_seconds: int = 3600
    token_type: str = "Bearer"


class OidcAuthorizationCodeClient:
    """Start and complete one-use Authorization Code + PKCE transactions.

    All endpoints and client metadata are operator configuration. No endpoint is learned
    from an untrusted JWT, callback parameter, or model output. This client intentionally
    supports public clients only: no client secret is accepted or stored.
    """

    def __init__(
        self,
        *,
        authorization_endpoint: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str,
        authenticator: OidcJwksAuthenticator,
        scopes: tuple[str, ...] = ("openid", "profile", "email"),
        transaction_ttl_seconds: int = 300,
        timeout_seconds: float = 5.0,
        token_exchange: Callable[[str, Mapping[str, str], float], bytes] | None = None,
        pending_store: PendingLoginStore | None = None,
    ) -> None:
        _validate_https_endpoint(authorization_endpoint, "Authorization endpoint")
        _validate_https_endpoint(token_endpoint, "Token endpoint")
        _validate_https_endpoint(redirect_uri, "Redirect URI")
        if not isinstance(client_id, str) or not client_id or client_id != client_id.strip():
            raise IdentityError("OIDC client ID must be explicit and trimmed.")
        if not isinstance(authenticator, OidcJwksAuthenticator):
            raise IdentityError("OIDC login requires the configured OIDC JWKS authenticator.")
        if (not isinstance(scopes, tuple) or "openid" not in scopes
                or any(not isinstance(scope, str) or not scope or scope != scope.strip() for scope in scopes)
                or len(set(scopes)) != len(scopes)):
            raise IdentityError("OIDC scopes must be a unique tuple containing openid.")
        if (isinstance(transaction_ttl_seconds, bool) or not isinstance(transaction_ttl_seconds, int)
                or not 30 <= transaction_ttl_seconds <= 600):
            raise IdentityError("OIDC transaction TTL must be between 30 and 600 seconds.")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0.1 <= timeout_seconds <= 10):
            raise IdentityError("OIDC token request timeout must be between 0.1 and 10 seconds.")
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._authenticator = authenticator
        self._scopes = scopes
        self._ttl = transaction_ttl_seconds
        self._timeout = float(timeout_seconds)
        self._exchange = token_exchange or _post_token_form
        # Memory is convenient for tests/single-process development. Multi-worker deployments
        # should inject EncryptedSQLitePendingLoginStore (or another atomic protected store).
        self._pending_store = pending_store if pending_store is not None else InMemoryPendingLoginStore(max_entries=1024)

    @staticmethod
    def _random_urlsafe(size: int = 32) -> str:
        return secrets.token_urlsafe(size)

    def begin_login(self) -> LoginStart:
        """Create a state/nonce/PKCE transaction and return the trusted authorization URL."""
        verifier = self._random_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        state = self._random_urlsafe(32)
        nonce = self._random_urlsafe(32)
        expires_at = time.time() + self._ttl
        try:
            self._pending_store.put(state, verifier, nonce, expires_at)
        except Exception:
            raise IdentityError("OIDC login transaction could not be stored safely; retry later.") from None
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": " ".join(self._scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        parsed = urlsplit(self._authorization_endpoint)
        query = urlencode(params)
        return LoginStart(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")), state, self._ttl)

    def complete_login(self, *, code: str, state: str) -> OidcLoginResult:
        """Exchange a one-use callback code, verify ID-token signature/claims/nonce, and return identity."""
        if not isinstance(state, str) or not state or len(state) > 512:
            raise IdentityError("OIDC callback state is invalid.")
        if not isinstance(code, str) or not code or len(code) > _MAX_AUTH_CODE_CHARS:
            raise IdentityError("OIDC authorization code is invalid.")
        # The store must atomically consume before network I/O to prevent callback replay/races.
        try:
            transaction = self._pending_store.consume(state)
        except Exception:
            raise IdentityError("OIDC login transaction could not be consumed safely.") from None
        if transaction is None:
            raise IdentityError("OIDC login state is unknown, expired, or already consumed.")

        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri,
            "client_id": self._client_id,
            "code_verifier": transaction.verifier,
        }
        try:
            raw = self._exchange(self._token_endpoint, fields, self._timeout)
            if not isinstance(raw, bytes) or len(raw) > _MAX_TOKEN_RESPONSE_BYTES:
                raise IdentityError("OIDC token exchange returned invalid or oversized data.")
            response = json.loads(raw.decode("utf-8"))
        except IdentityError:
            raise
        except Exception:
            raise IdentityError("OIDC token response is not valid JSON.") from None
        if not isinstance(response, dict):
            raise IdentityError("OIDC token response must be a JSON object.")
        id_token = response.get("id_token")
        access_token = response.get("access_token")
        token_type = response.get("token_type")
        expires_in = response.get("expires_in", 3600)
        if not isinstance(id_token, str) or not id_token or len(id_token) > 32 * 1024:
            raise IdentityError("OIDC token response is missing a valid ID token.")
        if not isinstance(access_token, str) or not access_token or len(access_token) > 32 * 1024:
            raise IdentityError("OIDC token response is missing a valid access token.")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise IdentityError("OIDC token response must use the Bearer token type.")
        if isinstance(expires_in, bool) or not isinstance(expires_in, int) or not 1 <= expires_in <= 86_400:
            raise IdentityError("OIDC access-token lifetime is invalid.")
        # Refresh tokens are intentionally unsupported until encrypted persistence and revocation exist.
        if response.get("refresh_token") is not None:
            raise IdentityError("OIDC refresh tokens are not supported by this client.")
        principal = self._authenticator.authenticate(id_token, expected_nonce=transaction.nonce)
        return OidcLoginResult(principal, access_token, expires_in, token_type)
