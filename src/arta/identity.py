"""JWT-verified approver identity and trusted approval issuance.

This module is an application-boundary component: callers submit a bearer token, not an
approver_id. The token is verified against operator-configured public keys and fixed issuer,
audience, and algorithms before an action-bound HMAC approval is issued and persisted.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable

try:
    import jwt
except ImportError:  # pragma: no cover - exercised only in misconfigured installations
    jwt = None  # type: ignore[assignment]

from .approvals import HmacApprovalAuthority
from .core import Approval, MissionError
from .persistence import SQLiteMissionStore


class IdentityError(PermissionError):
    """Raised when token verification or approval authorization fails."""


_SUPPORTED_ASYMMETRIC_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
})


@runtime_checkable
class PrincipalAuthenticator(Protocol):
    """Structural contract shared by fixed-key and OIDC/JWKS authenticators."""

    def authenticate(self, bearer_token: str) -> "AuthenticatedPrincipal":
        """Return verified identity claims or raise IdentityError."""


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Identity claims produced only after a verified token decode."""

    subject: str
    issuer: str
    audience: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    token_id: str | None = None


class JwtPrincipalAuthenticator:
    """Verify bearer JWTs using an operator-configured public-key allowlist.

    keys_by_kid maps a trusted key id to (fixed_algorithm, PEM_public_key). Obtain and
    rotate these keys through a trusted identity-provider/JWKS configuration process;
    this class intentionally does not fetch keys from URLs supplied by the token.
    """

    def __init__(
        self,
        *,
        keys_by_kid: Mapping[str, tuple[str, str | bytes]],
        issuer: str,
        audience: str,
        scope_claim: str | None = "scope",
        max_token_lifetime_seconds: int = 3600,
        leeway_seconds: int = 0,
    ) -> None:
        if jwt is None:
            raise IdentityError("PyJWT[crypto] is required for JWT authentication.")
        if not isinstance(issuer, str) or not issuer.strip():
            raise IdentityError("A fixed trusted JWT issuer is required.")
        if not isinstance(audience, str) or not audience.strip():
            raise IdentityError("A fixed ARTA JWT audience is required.")
        if scope_claim is not None and (not isinstance(scope_claim, str) or not scope_claim.strip()):
            raise IdentityError("The JWT scope claim name must be explicit when scopes are required.")
        if (
            isinstance(max_token_lifetime_seconds, bool)
            or not isinstance(max_token_lifetime_seconds, int)
            or not 1 <= max_token_lifetime_seconds <= 24 * 60 * 60
        ):
            raise IdentityError("Maximum token lifetime must be between 1 second and 24 hours.")
        if (
            isinstance(leeway_seconds, bool)
            or not isinstance(leeway_seconds, int)
            or not 0 <= leeway_seconds <= 30
        ):
            raise IdentityError("JWT clock leeway must be between 0 and 30 seconds.")
        if not isinstance(keys_by_kid, Mapping) or not keys_by_kid:
            raise IdentityError("At least one trusted public key must be configured.")

        checked: dict[str, tuple[str, str | bytes]] = {}
        for key_id, configured in keys_by_kid.items():
            if not isinstance(key_id, str) or not key_id or key_id != key_id.strip():
                raise IdentityError("Configured JWT key IDs must be non-empty and trimmed.")
            if (
                not isinstance(configured, tuple)
                or len(configured) != 2
                or not isinstance(configured[0], str)
                or configured[0] not in _SUPPORTED_ASYMMETRIC_ALGORITHMS
                or not isinstance(configured[1], (str, bytes))
                or not configured[1]
            ):
                raise IdentityError("Each JWT key must define a supported asymmetric algorithm and public key.")
            checked[key_id] = (configured[0], configured[1])

        self._keys_by_kid = MappingProxyType(checked)
        self._issuer = issuer.strip()
        self._audience = audience.strip()
        self._scope_claim = scope_claim.strip() if scope_claim is not None else None
        self._max_token_lifetime_seconds = max_token_lifetime_seconds
        self._leeway_seconds = leeway_seconds

    @staticmethod
    def _numeric_timestamp(value: object, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise IdentityError(f"JWT {label} claim must be a finite numeric timestamp.")
        return float(value)

    def authenticate(self, bearer_token: str) -> AuthenticatedPrincipal:
        """Authenticate a raw JWT or an HTTP Authorization: Bearer value."""
        if not isinstance(bearer_token, str) or not bearer_token.strip():
            raise IdentityError("A bearer token is required.")
        token = bearer_token.strip()
        if token[:7].lower() == "bearer ":
            token = token[7:].strip()
        if not token or len(token) > 32 * 1024:
            raise IdentityError("Bearer token is empty or exceeds the maximum accepted size.")

        try:
            header = jwt.get_unverified_header(token)
            if not isinstance(header, dict):
                raise IdentityError("JWT header is invalid.")
            key_id = header.get("kid")
            algorithm = header.get("alg")
            configured = self._keys_by_kid.get(key_id) if isinstance(key_id, str) else None
            if configured is None:
                raise IdentityError("JWT signing key is not trusted.")
            expected_algorithm, public_key = configured
            if algorithm != expected_algorithm or algorithm not in _SUPPORTED_ASYMMETRIC_ALGORITHMS:
                raise IdentityError("JWT signing algorithm does not match the configured key.")

            claims = jwt.decode(
                token,
                key=public_key,
                algorithms=[expected_algorithm],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway_seconds,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"] + ([self._scope_claim] if self._scope_claim else []),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
            subject = claims.get("sub")
            if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
                raise IdentityError("JWT subject is invalid.")
            issued_at = self._numeric_timestamp(claims.get("iat"), "iat")
            expires_at = self._numeric_timestamp(claims.get("exp"), "exp")
            if expires_at <= issued_at:
                raise IdentityError("JWT lifetime is invalid.")
            if expires_at - issued_at > self._max_token_lifetime_seconds:
                raise IdentityError("JWT lifetime exceeds the configured maximum.")

            if self._scope_claim is None:
                # OIDC ID tokens commonly do not carry OAuth scopes; identity alone grants no tool permission.
                scopes = frozenset()
            else:
                raw_scopes = claims.get(self._scope_claim)
                if not isinstance(raw_scopes, str) or len(raw_scopes) > 8192:
                    raise IdentityError("JWT scope claim must be a bounded space-delimited string.")
                scopes = frozenset(raw_scopes.split())
                if not scopes or len(scopes) > 128 or any(len(item) > 256 for item in scopes):
                    raise IdentityError("JWT scope claim is empty or exceeds its bounds.")
            token_id = claims.get("jti")
            if token_id is not None and (
                not isinstance(token_id, str) or not token_id.strip() or len(token_id) > 512
            ):
                raise IdentityError("JWT token ID is invalid.")

            return AuthenticatedPrincipal(
                subject=subject.strip(),
                issuer=self._issuer,
                audience=self._audience,
                scopes=scopes,
                issued_at=issued_at,
                expires_at=expires_at,
                token_id=token_id,
            )
        except IdentityError:
            raise
        except Exception:
            # Never return decoder details, token fragments, or claims to callers.
            raise IdentityError("Bearer token failed cryptographic or claim validation.") from None


class TrustedApprovalService:
    """Issue persisted action-bound approvals only after verified identity and scope checks."""

    def __init__(
        self,
        *,
        authenticator: PrincipalAuthenticator,
        authority: HmacApprovalAuthority,
        store: SQLiteMissionStore,
        required_scopes_by_tool: Mapping[str, Sequence[str]],
        max_approval_lifetime_seconds: int = 300,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(authenticator, PrincipalAuthenticator):
            raise IdentityError("A compatible verified-principal authenticator is required.")
        if not isinstance(authority, HmacApprovalAuthority):
            raise IdentityError("A trusted HMAC approval authority is required.")
        if not isinstance(store, SQLiteMissionStore):
            raise IdentityError("A SQLiteMissionStore is required for durable approval issuance.")
        if (
            isinstance(max_approval_lifetime_seconds, bool)
            or not isinstance(max_approval_lifetime_seconds, int)
            or not 1 <= max_approval_lifetime_seconds <= 900
        ):
            raise IdentityError("Maximum approval lifetime must be between 1 and 900 seconds.")
        if not isinstance(required_scopes_by_tool, Mapping) or not required_scopes_by_tool:
            raise IdentityError("An explicit map of tools requiring approval scopes is required.")

        checked: dict[str, tuple[str, ...]] = {}
        for tool_name, scopes in required_scopes_by_tool.items():
            if not isinstance(tool_name, str) or not tool_name or tool_name != tool_name.strip():
                raise IdentityError("Configured approval tool names must be non-empty and trimmed.")
            if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
                raise IdentityError("Each tool's extra approval scopes must be an explicit sequence.")
            extra = tuple(scopes)
            if any(not isinstance(scope, str) or not scope or scope != scope.strip() for scope in extra):
                raise IdentityError("Configured approval scopes must be non-empty and trimmed.")
            if len(set(extra)) != len(extra):
                raise IdentityError("Configured approval scopes must be unique.")
            checked[tool_name] = extra

        self._authenticator = authenticator
        self._authority = authority
        self._store = store
        self._required_scopes_by_tool = MappingProxyType(checked)
        self._max_approval_lifetime_seconds = max_approval_lifetime_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def issue_approval(
        self,
        bearer_token: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        *,
        lifetime_seconds: int = 120,
    ) -> Approval:
        """Verify identity and tool-specific permission, then sign and durably persist approval."""
        if not isinstance(tool_name, str) or not tool_name or tool_name != tool_name.strip():
            raise IdentityError("An exact registered tool name is required.")
        extra_scopes = self._required_scopes_by_tool.get(tool_name)
        if extra_scopes is None:
            raise IdentityError("This tool is not configured for trusted approval issuance.")
        if (
            isinstance(lifetime_seconds, bool)
            or not isinstance(lifetime_seconds, int)
            or not 1 <= lifetime_seconds <= self._max_approval_lifetime_seconds
        ):
            raise IdentityError("Requested approval lifetime is outside the configured bound.")

        principal = self._authenticator.authenticate(bearer_token)
        required_scopes = {"arta:approve", f"arta:approve:{tool_name}", *extra_scopes}
        if not required_scopes.issubset(principal.scopes):
            raise IdentityError("Authenticated principal lacks the required approval scope.")

        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise IdentityError("Trusted approval clock must return a timezone-aware datetime.")
        now = now.astimezone(timezone.utc)
        token_expiry = datetime.fromtimestamp(principal.expires_at, tz=timezone.utc)
        expires_at = min(now + timedelta(seconds=lifetime_seconds), token_expiry)
        if expires_at <= now:
            raise IdentityError("Identity token has insufficient lifetime for a new approval.")

        try:
            approval = self._authority.issue(
                tool_name,
                dict(arguments) if arguments is not None else None,
                approver_id=principal.subject,
                approved_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
            )
            self._store.put_approval(approval)
        except MissionError:
            raise
        except Exception:
            # Do not disclose database detail, token content, or signed approval payloads.
            raise IdentityError("Trusted approval could not be durably issued.") from None
        return approval
