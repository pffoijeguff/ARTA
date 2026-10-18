from __future__ import annotations

import base64
import io
import json

import pytest

from arta.identity import AuthenticatedPrincipal, IdentityError
from arta.oidc_login import LoginStart, OidcLoginResult
from arta.oidc_sessions import SQLiteOidcSessionStore
from arta.oidc_web import OidcWebApplication, create_app_from_environment


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
            principal=AuthenticatedPrincipal(subject="verified-user", issuer="https://identity.example.test/", audience="arta-web", scopes=frozenset(), issued_at=1_700_000_000, expires_at=1_700_003_600),
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

    status, headers, callback_body = invoke(
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
    assert callback_body == b""
    assert all("provider-access-token" not in value for _, value in headers)

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



def test_persian_home_page_renders_login_and_escapes_authenticated_subject(tmp_path):
    store = SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x71" * 32)
    app = OidcWebApplication(
        login_client=FakeLogin(),
        session_store=store,
        public_origin="https://app.example.test",
        callback_path="/oidc/callback",
    )
    status, headers, body = invoke(app, "/")
    assert status == "200 OK"
    assert "text/html; charset=utf-8" in header_values(headers, "Content-Type")[0]
    assert 'lang="fa" dir="rtl"' in body.decode()
    assert "/login" in body.decode()

    session = store.create_session('<img src=x onerror="alert(1)">')
    status, _, body = invoke(app, "/", cookie=f"arta_session={session.token}")
    page = body.decode()
    assert status == "200 OK"
    assert "&lt;img" in page
    assert '<img src=x' not in page
    assert "/logout" in page



@pytest.mark.parametrize("callback_path", ["/", "/login", "/session", "/logout", "//attacker.example", "/callback?x=1"])
def test_web_adapter_rejects_callback_route_collisions_and_unsafe_paths(tmp_path, callback_path):
    with pytest.raises(ValueError, match="callback_path"):
        OidcWebApplication(
            login_client=FakeLogin(),
            session_store=SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", b"\x72" * 32),
            public_origin="https://app.example.test",
            callback_path=callback_path,
        )



def _oidc_environment(tmp_path, *, transaction_key=b"\x81" * 32, session_key=b"\x82" * 32):
    return {
        "ARTA_OIDC_JWKS_URL": "https://identity.example.test/.well-known/jwks.json",
        "ARTA_OIDC_ISSUER": "https://identity.example.test/",
        "ARTA_OIDC_AUDIENCE": "arta-web",
        "ARTA_OIDC_AUTHORIZATION_ENDPOINT": "https://identity.example.test/authorize",
        "ARTA_OIDC_TOKEN_ENDPOINT": "https://identity.example.test/token",
        "ARTA_OIDC_CLIENT_ID": "arta-web",
        "ARTA_OIDC_REDIRECT_URI": "https://app.example.test/oidc/callback",
        "ARTA_OIDC_TRANSACTION_DB": str(tmp_path / "transactions.sqlite3"),
        "ARTA_OIDC_SESSION_DB": str(tmp_path / "sessions.sqlite3"),
        "ARTA_OIDC_TRANSACTION_KEY_B64": base64.b64encode(transaction_key).decode("ascii"),
        "ARTA_OIDC_SESSION_KEY_B64": base64.b64encode(session_key).decode("ascii"),
    }


def test_environment_factory_builds_configured_app_without_network_access(tmp_path):
    app = create_app_from_environment(_oidc_environment(tmp_path))
    assert isinstance(app, OidcWebApplication)
    assert (tmp_path / "transactions.sqlite3").exists()
    assert (tmp_path / "sessions.sqlite3").exists()


def test_environment_factory_rejects_missing_or_reused_keys(tmp_path):
    env = _oidc_environment(tmp_path)
    env.pop("ARTA_OIDC_AUDIENCE")
    with pytest.raises(ValueError, match="ARTA_OIDC_AUDIENCE"):
        create_app_from_environment(env)

    env = _oidc_environment(tmp_path, transaction_key=b"\x83" * 32, session_key=b"\x83" * 32)
    with pytest.raises(ValueError, match="must be different"):
        create_app_from_environment(env)


def test_environment_factory_rejects_bad_key_encoding_and_callback_uri(tmp_path):
    env = _oidc_environment(tmp_path)
    env["ARTA_OIDC_SESSION_KEY_B64"] = "not valid base64!"
    with pytest.raises(ValueError, match="valid base64"):
        create_app_from_environment(env)

    env = _oidc_environment(tmp_path)
    env["ARTA_OIDC_REDIRECT_URI"] = "http://app.example.test/oidc/callback"
    with pytest.raises(ValueError, match="dedicated HTTPS callback"):
        create_app_from_environment(env)


def test_environment_factory_rejects_shared_database_path(tmp_path):
    env = _oidc_environment(tmp_path)
    env["ARTA_OIDC_SESSION_DB"] = env["ARTA_OIDC_TRANSACTION_DB"]
    with pytest.raises(ValueError, match="separate files"):
        create_app_from_environment(env)
