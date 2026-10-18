# OIDC WSGI web adapter

ARTA now includes `OidcWebApplication`, a small WSGI adapter that connects the existing PKCE client and opaque SQLite session store to real HTTP request/response handling without adding a web-framework dependency.

## Routes

| Route | Method | Behavior |
| --- | --- | --- |
| `/login` | GET | Starts Authorization Code + PKCE, sets a per-transaction browser-binding cookie, then redirects to the configured HTTPS authorization endpoint. |
| Configured callback path | GET | Requires exactly one code and state plus the matching browser-binding cookie; validates the OIDC response; creates an opaque local session; clears the binding cookie; redirects to a configured local path. |
| `/session` | GET | Returns only authenticated status, verified subject and session expiry. It never returns provider tokens. |
| `/logout` | POST | Requires an exact same-origin `Origin` header, revokes the local session, and clears its cookie. |

All responses include no-store caching controls, a restrictive content-security policy, `nosniff`, and `no-referrer`. Callback failures are deliberately generic and do not echo provider errors, codes, state, or cookies. Duplicate callback parameters fail closed. Redirect destinations are configured local paths, not callback-controlled URLs.

## Minimal integration

Create the JWKS authenticator, login client, encrypted pending-login store and encrypted session store using the deployment's trusted provider configuration and separate secret-manager keys. Then wrap the WSGI app:

```python
from arta import (
    EncryptedSQLitePendingLoginStore,
    OidcAuthorizationCodeClient,
    OidcJwksAuthenticator,
    OidcWebApplication,
    SQLiteOidcSessionStore,
)

authenticator = OidcJwksAuthenticator(
    jwks_url="https://id.example/.well-known/jwks.json",
    issuer="https://id.example/",
    audience="arta-web",
)
login = OidcAuthorizationCodeClient(
    authorization_endpoint="https://id.example/authorize",
    token_endpoint="https://id.example/token",
    client_id="arta-web",
    redirect_uri="https://app.example/oidc/callback",
    authenticator=authenticator,
    pending_store=EncryptedSQLitePendingLoginStore(
        "/var/lib/arta/oidc-transactions.sqlite3",
        encryption_key=load_secret("ARTA_OIDC_TRANSACTION_KEY"),  # application adapter
    ),
)
application = OidcWebApplication(
    login_client=login,
    session_store=SQLiteOidcSessionStore(
        "/var/lib/arta/oidc-sessions.sqlite3",
        encryption_key=load_secret("ARTA_OIDC_SESSION_KEY"),  # separate key
    ),
    public_origin="https://app.example",
    callback_path="/oidc/callback",
    session_ttl_seconds=3600,
)
```

The `load_secret` function above is intentionally a placeholder for the deployment's secret manager. Each key must be exactly 32 random bytes and must not be committed, logged, or reused for another security purpose. The reverse proxy and identity provider must register the exact callback URI `https://app.example/oidc/callback`.

Mount `application` under a WSGI server behind a correctly configured TLS-terminating reverse proxy. Keep the app and databases private; protect database directories, SQLite WAL files and backups; restrict network access; and ensure the proxy preserves the correct host and origin. The adapter accepts only an HTTPS `public_origin` and sets `Secure; HttpOnly; SameSite=Lax; Path=/` host-only cookies. It intentionally has no insecure production-cookie switch; non-Secure cookies are accepted only for localhost development.

## Environment-driven application factory

For a deployment that uses environment-injected secrets, the package exports `create_app_from_environment()`. It reads the settings below, validates them, requires distinct 32-byte keys for transaction and session encryption, requires separate SQLite database files, and constructs the JWKS authenticator, PKCE client, encrypted stores, and WSGI app without contacting the identity provider during startup.

Required settings:

| Variable | Meaning |
| --- | --- |
| `ARTA_OIDC_JWKS_URL` | Fixed HTTPS JWKS URL from trusted provider configuration. |
| `ARTA_OIDC_ISSUER` | Exact expected HTTPS issuer. |
| `ARTA_OIDC_AUDIENCE` | Registered OIDC client ID / expected audience. |
| `ARTA_OIDC_AUTHORIZATION_ENDPOINT` | Fixed HTTPS authorization endpoint. |
| `ARTA_OIDC_TOKEN_ENDPOINT` | Fixed HTTPS token endpoint. |
| `ARTA_OIDC_CLIENT_ID` | Registered client ID. |
| `ARTA_OIDC_REDIRECT_URI` | Exact registered HTTPS callback URI, including its path. |
| `ARTA_OIDC_TRANSACTION_DB` | Dedicated durable SQLite file for pending PKCE transactions. |
| `ARTA_OIDC_SESSION_DB` | Different durable SQLite file for local sessions. |
| `ARTA_OIDC_TRANSACTION_KEY_B64` | Base64 encoding of a random 32-byte transaction key. |
| `ARTA_OIDC_SESSION_KEY_B64` | Base64 encoding of a different random 32-byte session key. |

Optional settings are `ARTA_OIDC_TRANSACTION_TTL_SECONDS` (30–600, default 300), `ARTA_OIDC_SESSION_TTL_SECONDS` (60–2592000, default 3600), and `ARTA_OIDC_AFTER_LOGIN_PATH` (default `/`, local absolute path only).

With Gunicorn installed in the deployment environment, a factory-based entry point can be started with:

```sh
gunicorn 'arta.oidc_web:create_app_from_environment()' --bind 127.0.0.1:8000 --workers 2
```

Bind the app to loopback behind a TLS-terminating reverse proxy, or use an appropriately secured private network. Configure the proxy to preserve the expected public host/origin and never log callback query strings, cookies, authorization codes, or tokens. Supply secrets through your orchestrator/secret manager as environment values; do not commit them in `.env` files. The exact callback URL registered with the identity provider must match `ARTA_OIDC_REDIRECT_URI`.

This factory improves repeatable configuration; it does not prove that a provider's tenant, policies, DNS, proxy, TLS, browser behavior or production database backups are correctly configured.

## Explicit boundaries

This adapter provides HTTP routing and local session handling, but it is not a complete consumer-facing login product. It does not render a login UI, implement MFA or provider-wide logout, revoke provider-issued access tokens, supply secret-manager integration, configure DNS/TLS/proxy headers, or perform deployment-specific security testing. The host must add its own UI, account authorization policy, logging with sensitive-field redaction, rate limits and operational monitoring. A verified OIDC subject establishes identity, not ARTA tool permissions; permissions must still be granted separately by trusted policy.

Before public deployment, test against the actual identity provider and WSGI server/proxy, review cookie and origin behavior in supported browsers, exercise backup/restore and key rotation, and obtain an independent security review. The local test suite proves the adapter's coded contract, not production readiness.
