"""Minimal hardened WSGI adapter for the OIDC login and session primitives.

This adapter deliberately uses only the Python standard library. Put it behind a TLS-terminating
reverse proxy, configure the exact public origin, and do not log callback query strings or cookies.
"""
from __future__ import annotations

import base64
import hmac
import html
import json
import os
from http.cookies import CookieError, SimpleCookie
from typing import Callable, Iterable, Mapping
from urllib.parse import parse_qs, urlsplit

from .identity import IdentityError
from .oidc import OidcJwksAuthenticator
from .oidc_login import OidcAuthorizationCodeClient
from .pending_login_store import EncryptedSQLitePendingLoginStore
from .oidc_sessions import OidcSessionStoreError, SQLiteOidcSessionStore


class OidcWebApplication:
    """WSGI routes for login, OIDC callback, current session, and logout.

    The app serves a minimal Persian RTL home page and manages local HTTP sessions, but does not
    manage provider-side logout/MFA. It creates a local session only from a verified OIDC principal.
    Cookies are host-only (no Domain attribute).
    """

    SESSION_COOKIE = "arta_session"
    _MAX_QUERY_BYTES = 16_384

    def __init__(
        self,
        *,
        login_client: OidcAuthorizationCodeClient,
        session_store: SQLiteOidcSessionStore,
        public_origin: str,
        callback_path: str,
        session_ttl_seconds: int = 3600,
        after_login_path: str = "/",
        secure_cookies: bool = True,
    ) -> None:
        parsed_origin = urlsplit(public_origin)
        if (
            parsed_origin.scheme != "https"
            or not parsed_origin.netloc
            or parsed_origin.path not in ("", "/")
            or parsed_origin.query
            or parsed_origin.fragment
            or parsed_origin.username is not None
            or parsed_origin.password is not None
        ):
            raise ValueError("public_origin must be an HTTPS origin without a path")
        if (
            not isinstance(callback_path, str)
            or not callback_path.startswith("/")
            or callback_path.startswith("//")
            or callback_path in {"/", "/login", "/session", "/logout"}
            or "?" in callback_path
            or "#" in callback_path
        ):
            raise ValueError("callback_path must be a dedicated local path without query or fragment")
        if not isinstance(after_login_path, str) or not after_login_path.startswith("/") or after_login_path.startswith("//") or "?" in after_login_path or "#" in after_login_path:
            raise ValueError("after_login_path must be an absolute local path without query or fragment")
        if isinstance(session_ttl_seconds, bool) or not isinstance(session_ttl_seconds, int) or not 60 <= session_ttl_seconds <= 30 * 24 * 60 * 60:
            raise ValueError("session TTL must be between 60 seconds and 30 days")
        if not isinstance(secure_cookies, bool):
            raise ValueError("secure_cookies must be a boolean")
        if not secure_cookies and parsed_origin.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("non-Secure cookies are allowed only for localhost development")
        self._login = login_client
        self._sessions = session_store
        self._origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"
        self._callback_path = callback_path
        self._session_ttl = session_ttl_seconds
        self._after_login_path = after_login_path
        self._secure = secure_cookies

    def _cookie(self, name: str, value: str, *, max_age: int, http_only: bool = True) -> str:
        parts = [f"{name}={value}", "Path=/", f"Max-Age={max(0, int(max_age))}", "SameSite=Lax"]
        if self._secure:
            parts.append("Secure")
        if http_only:
            parts.append("HttpOnly")
        return "; ".join(parts)

    @staticmethod
    def _headers(extra: Iterable[tuple[str, str]] = ()) -> list[tuple[str, str]]:
        return [
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
            *extra,
        ]

    @staticmethod
    def _response(start_response: Callable, status: str, body: bytes = b"", extra=()):
        headers = OidcWebApplication._headers(extra)
        if body:
            headers.append(("Content-Length", str(len(body))))
        start_response(status, headers)
        return [body]

    def _json(self, start_response: Callable, status: str, payload: dict, extra=()):
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return self._response(start_response, status, body, [("Content-Type", "application/json; charset=utf-8"), *extra])

    def _html(self, start_response: Callable, status: str, document: str):
        body = document.encode("utf-8")
        return self._response(start_response, status, body, [("Content-Type", "text/html; charset=utf-8")])

    @staticmethod
    def _cookies(environ) -> SimpleCookie:
        parsed = SimpleCookie()
        try:
            parsed.load(environ.get("HTTP_COOKIE", ""))
        except CookieError:
            raise ValueError("Malformed Cookie header") from None
        return parsed

    @staticmethod
    def _query(environ) -> dict[str, list[str]]:
        raw = environ.get("QUERY_STRING", "")
        if len(raw.encode("utf-8", errors="ignore")) > OidcWebApplication._MAX_QUERY_BYTES:
            raise ValueError("Query string too large")
        return parse_qs(raw, keep_blank_values=True, strict_parsing=False, max_num_fields=32)

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        try:
            if path == "/":
                if method != "GET":
                    return self._response(start_response, "405 Method Not Allowed", extra=[("Allow", "GET")])
                cookies = self._cookies(environ)
                token = cookies.get(self.SESSION_COOKIE)
                session = self._sessions.validate_session(token.value if token else "")
                if session is None:
                    document = """<!doctype html>
<html lang="fa" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARTA Ω∞ — ورود امن</title></head>
<body>
<main>
<header><p>ARTA Ω∞</p><h1>مرکز فرماندهی مأموریت‌ها</h1></header>
<section aria-labelledby="welcome">
<h2 id="welcome">به ARTA خوش آمدی</h2>
<p>برای ادامه، با ارائه‌دهندهٔ هویت پیکربندی‌شده وارد شو.</p>
<p><a href="/login">ورود امن با حساب کاربری</a></p>
</section>
<footer><p>ورود با OIDC و PKCE انجام می‌شود. ARTA تا پیش از تأیید هویت، نشست محلی ایجاد نمی‌کند.</p></footer>
</main>
</body></html>"""
                else:
                    safe_subject = html.escape(session.subject, quote=True)
                    expiry = html.escape(str(int(session.expires_at)), quote=True)
                    document = f"""<!doctype html>
<html lang="fa" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARTA Ω∞ — نشست فعال</title></head>
<body>
<main>
<header><p>ARTA Ω∞</p><h1>نشست امن فعال است</h1></header>
<section aria-labelledby="account">
<h2 id="account">حساب واردشده</h2>
<p><b>شناسهٔ کاربر:</b> <code>{safe_subject}</code></p>
<p><b>انقضای نشست (Unix timestamp):</b> <time>{expiry}</time></p>
<form action="/logout" method="post"><button type="submit">خروج امن</button></form>
</section>
<p><a href="/session">نمایش وضعیت نشست به‌صورت JSON</a></p>
</main>
</body></html>"""
                return self._html(start_response, "200 OK", document)

            if path == "/login":
                if method != "GET":
                    return self._json(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"}, [("Allow", "GET")])
                start = self._login.begin_login()
                cookie = self._cookie(start.browser_binding_cookie_name, start.browser_binding_cookie_value, max_age=start.expires_in_seconds)
                return self._response(start_response, "302 Found", extra=[("Location", start.authorization_url), ("Set-Cookie", cookie)])

            if path == self._callback_path:
                if method != "GET":
                    return self._json(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"}, [("Allow", "GET")])
                try:
                    query = self._query(environ)
                    state_values = query.get("state", [])
                    code_values = query.get("code", [])
                    if len(state_values) != 1 or len(code_values) != 1 or not state_values[0] or not code_values[0]:
                        raise ValueError("Invalid callback parameters")
                    state, code = state_values[0], code_values[0]
                    cookie_name = self._login.browser_binding_cookie_name(state)
                    cookie = self._cookies(environ)
                    binding = cookie.get(cookie_name)
                    if binding is None:
                        raise IdentityError("OIDC browser-binding cookie is missing.")
                    result = self._login.complete_login(code=code, state=state, browser_binding=binding.value)
                    session = self._sessions.create_session(result.principal.subject, ttl_seconds=self._session_ttl)
                    clear_binding = self._cookie(cookie_name, "", max_age=0)
                    session_cookie = self._cookie(self.SESSION_COOKIE, session.token, max_age=self._session_ttl)
                    return self._response(
                        start_response,
                        "303 See Other",
                        extra=[("Location", self._after_login_path), ("Set-Cookie", clear_binding), ("Set-Cookie", session_cookie)],
                    )
                except (ValueError, IdentityError):
                    # Do not echo provider error descriptions, callback values, or state to the browser.
                    return self._json(start_response, "400 Bad Request", {"error": "login_failed"})

            if path == "/session":
                if method != "GET":
                    return self._json(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"}, [("Allow", "GET")])
                cookies = self._cookies(environ)
                token = cookies.get(self.SESSION_COOKIE)
                session = self._sessions.validate_session(token.value if token else "")
                if session is None:
                    return self._json(start_response, "401 Unauthorized", {"error": "unauthenticated"})
                return self._json(start_response, "200 OK", {
                    "authenticated": True,
                    "subject": session.subject,
                    "expires_at": session.expires_at,
                })

            if path == "/logout":
                if method != "POST":
                    return self._json(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"}, [("Allow", "POST")])
                if environ.get("HTTP_ORIGIN") != self._origin:
                    return self._json(start_response, "403 Forbidden", {"error": "origin_rejected"})
                cookies = self._cookies(environ)
                token = cookies.get(self.SESSION_COOKIE)
                if token is not None:
                    self._sessions.revoke_session(token.value)
                clear = self._cookie(self.SESSION_COOKIE, "", max_age=0)
                return self._response(start_response, "204 No Content", extra=[("Set-Cookie", clear)])

            return self._json(start_response, "404 Not Found", {"error": "not_found"})
        except (ValueError, CookieError):
            return self._json(start_response, "400 Bad Request", {"error": "bad_request"})
        except OidcSessionStoreError:
            return self._json(start_response, "503 Service Unavailable", {"error": "session_store_unavailable"})
        except Exception:
            # Fail closed; details belong in a redacted server-side logger configured by the host.
            return self._json(start_response, "500 Internal Server Error", {"error": "internal_error"})



def create_app_from_environment(env: Mapping[str, str] | None = None) -> OidcWebApplication:
    """Build a WSGI app from explicit environment configuration and secret-manager injection.

    Secret values are base64-encoded 32-byte keys. The deployment should inject them through
    its secret manager/orchestrator, never store them in the repository or a checked-in .env file.
    """
    config = os.environ if env is None else env

    def required(name: str) -> str:
        value = config.get(name, "")
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError(f"required environment setting {name} is missing or untrimmed")
        return value

    def key_from_env(name: str) -> bytes:
        encoded = required(name)
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise ValueError(f"environment setting {name} must be valid base64") from None
        if len(key) != 32:
            raise ValueError(f"environment setting {name} must decode to exactly 32 bytes")
        return key

    jwks_url = required("ARTA_OIDC_JWKS_URL")
    issuer = required("ARTA_OIDC_ISSUER")
    audience = required("ARTA_OIDC_AUDIENCE")
    authorization_endpoint = required("ARTA_OIDC_AUTHORIZATION_ENDPOINT")
    token_endpoint = required("ARTA_OIDC_TOKEN_ENDPOINT")
    client_id = required("ARTA_OIDC_CLIENT_ID")
    redirect_uri = required("ARTA_OIDC_REDIRECT_URI")
    transaction_db = required("ARTA_OIDC_TRANSACTION_DB")
    session_db = required("ARTA_OIDC_SESSION_DB")
    transaction_key = key_from_env("ARTA_OIDC_TRANSACTION_KEY_B64")
    session_key = key_from_env("ARTA_OIDC_SESSION_KEY_B64")
    if hmac.compare_digest(transaction_key, session_key):
        raise ValueError("OIDC transaction and session encryption keys must be different")
    if os.path.realpath(transaction_db) == os.path.realpath(session_db):
        raise ValueError("OIDC transaction and session databases must use separate files")

    redirect = urlsplit(redirect_uri)
    if (
        redirect.scheme != "https"
        or not redirect.hostname
        or redirect.username is not None
        or redirect.password is not None
        or redirect.query
        or redirect.fragment
        or not redirect.path
        or redirect.path in {"/", "/login", "/session", "/logout"}
        or redirect.path.startswith("//")
    ):
        raise ValueError("ARTA_OIDC_REDIRECT_URI must be a dedicated HTTPS callback URL")
    public_origin = f"{redirect.scheme}://{redirect.netloc}"

    try:
        transaction_ttl = int(config.get("ARTA_OIDC_TRANSACTION_TTL_SECONDS", "300"))
        session_ttl = int(config.get("ARTA_OIDC_SESSION_TTL_SECONDS", "3600"))
    except (TypeError, ValueError):
        raise ValueError("OIDC TTL environment settings must be integers") from None
    if not 30 <= transaction_ttl <= 600:
        raise ValueError("ARTA_OIDC_TRANSACTION_TTL_SECONDS must be between 30 and 600")
    if not 60 <= session_ttl <= 30 * 24 * 60 * 60:
        raise ValueError("ARTA_OIDC_SESSION_TTL_SECONDS must be between 60 and 2592000")

    authenticator = OidcJwksAuthenticator(
        jwks_url=jwks_url,
        issuer=issuer,
        audience=audience,
    )
    login_client = OidcAuthorizationCodeClient(
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        authenticator=authenticator,
        transaction_ttl_seconds=transaction_ttl,
        pending_store=EncryptedSQLitePendingLoginStore(transaction_db, transaction_key),
    )
    return OidcWebApplication(
        login_client=login_client,
        session_store=SQLiteOidcSessionStore(session_db, session_key),
        public_origin=public_origin,
        callback_path=redirect.path,
        session_ttl_seconds=session_ttl,
        after_login_path=config.get("ARTA_OIDC_AFTER_LOGIN_PATH", "/"),
    )
