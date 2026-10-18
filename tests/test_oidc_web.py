from __future__ import annotations

import io
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from arta.identity import AuthenticatedPrincipal, IdentityError
from arta.oidc_login import LoginStart, OidcLoginResult
from arta.oidc_sessions import SQLiteOidcSessionStore
from arta.oidc_web import OidcWebApplication


class FakeLogin:
    def __init__(self):
        self.start = None
        self.calls = []

    @staticmethod
    def browser_binding_cookie_name(state):
        from arta.oidc_login import OidcAuthorizationCodeClient
        return OidcAuthorizationCodeClient.browser_binding_cookie_name(state)

    def begin_login(self):
        self.start = LoginStart(
            "https://identity.example.test/authorize?client_id=arta",
            "test-state-value",
            300,
            self.browser_binding_cookie_name("test-state-value"),
            "secret-browser-binding",
        )
        return self.start

    def complete_login(self, *, code, state, browser_binding):
        self.calls.append((code, state, browser_binding))
        if state != self.start.state or browser_binding != self.start.browser_binding_cookie_value or code != "valid-code":
            raise IdentityError("bad callback")
        return OidcLoginResult(
            principal=AuthenticatedPrincipal(subject="verified-user", scopes=frozenset()),
            access_token="provider-access-token-that-must-not-be-returned",
        )


def invoke(app, path, *, method="GET", query="", cookie="", origin=None):
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "HTTP_COOKIE": cookie,
        "SERVER_NAME": "app.example.test",
        "SERVER_PORT": "443",
        "wsgi.url_scheme": "https",
        "wsgi.input": io.BytesIO(b""),
    }
    if origin is not None:
        environ["HTTP_ORIGIN"] = origin
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


def header_values(headers, name):
    return [value for key, value in headers if key.lower() == name.lower()]


def cookie_pair(set_cookie):
    return set_cookie.split(";", 1)[0]


def test_login_callback_session_and_logout_flow(tmp_path):
    login = FakeLogin()
    store = SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x61" * 32)
    app = OidcWebApplication(
        login_client=login,
        session_store=store,
        public_origin="https://app.example.test",
        callback_path="/oidc/callback",
    )

    status, headers, _ = invoke(app, "/login")
    assert status == "302 Found"
    assert header_values(headers, "Location") == [login.start.authorization_url]
    binding_cookie = header_values(headers, "Set-Cookie")[0]
    assert "Secure" in binding_cookie and "HttpOnly" in binding_cookie and "SameSite=Lax" in binding_cookie

    status, headers, _ = invoke(
        app,
        "/oidc/callback",
        query="code=valid-code&state=test-state-value",
        cookie=cookie_pair(binding_cookie),
    )
    assert status == "303 See Other"
    assert header_values(headers, "Location") == ["/"]
    cookies = header_values(headers, "Set-Cookie")
    assert len(cookies) == 2
    assert any("Max-Age=0" in value and login.start.browser_binding_cookie_name in value for value in cookies)
    session_cookie = next(value for value in cookies if value.startswith("arta_session="))
    assert "Secure" in session_cookie and "HttpOnly" in session_cookie and "SameSite=Lax" in session_cookie
    assert b"provider-access-token" not in b"".join(headers.__repr__().encode() for _ in range(1))

    status, _, body = invoke(app, "/session", cookie=cookie_pair(session_cookie))
    assert status == "200 OK"
    payload = json.loads(body)
    assert payload["authenticated"] is True
    assert payload["subject"] == "verified-user"
    assert "access_token" not in payload

    status, _, body = invoke(app, "/logout", method="POST", cookie=cookie_pair(session_cookie), origin="https://attacker.example")
    assert status == "403 Forbidden"
    assert json.loads(body)["error"] == "origin_rejected"
    assert invoke(app, "/session", cookie=cookie_pair(session_cookie))[0] == "200 OK"

    status, headers, _ = invoke(app, "/logout", method="POST", cookie=cookie_pair(session_cookie), origin="https://app.example.test")
    assert status == "204 No Content"
    assert "Max-Age=0" in header_values(headers, "Set-Cookie")[0]
    assert invoke(app, "/session", cookie=cookie_pair(session_cookie))[0] == "401 Unauthorized"


def test_callback_without_browser_binding_does_not_exchange_code(tmp_path):
    login = FakeLogin()
    app = OidcWebApplication(
        login_client=login,
        session_store=SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x62" * 32),
        public_origin="https://app.example.test",
        callback_path="/oidc/callback",
    )
    login.begin_login()
    status, _, body = invoke(app, "/oidc/callback", query="code=valid-code&state=test-state-value")
    assert status == "400 Bad Request"
    assert json.loads(body)["error"] == "login_failed"
    assert login.calls == []


def test_callback_duplicate_parameters_fail_closed(tmp_path):
    login = FakeLogin()
    app = OidcWebApplication(
        login_client=login,
        session_store=SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x63" * 32),
        public_origin="https://app.example.test",
        callback_path="/oidc/callback",
    )
    login.begin_login()
    status, _, _ = invoke(
        app, "/oidc/callback",
        query="code=valid-code&code=attacker-code&state=test-state-value",
        cookie=f"{login.start.browser_binding_cookie_name}={login.start.browser_binding_cookie_value}",
    )
    assert status == "400 Bad Request"
    assert login.calls == []


def test_web_adapter_rejects_unsafe_origins_and_redirect_paths(tmp_path):
    store = SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x64" * 32)
    login = FakeLogin()
    with pytest.raises(ValueError, match="HTTPS origin"):
        OidcWebApplication(
            login_client=login, session_store=store,
            public_origin="http://app.example.test", callback_path="/oidc/callback",
        )
    with pytest.raises(ValueError, match="after_login_path"):
        OidcWebApplication(
            login_client=login, session_store=store,
            public_origin="https://app.example.test", callback_path="/oidc/callback",
            after_login_path="//attacker.example",
        )


def test_unauthenticated_session_and_method_restrictions(tmp_path):
    app = OidcWebApplication(
        login_client=FakeLogin(),
        session_store=SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x65" * 32),
        public_origin="https://app.example.test",
        callback_path="/oidc/callback",
    )
    assert invoke(app, "/session")[0] == "401 Unauthorized"
    assert invoke(app, "/logout", method="GET")[0] == "405 Method Not Allowed"
    assert invoke(app, "/login", method="POST")[0] == "405 Method Not Allowed"
