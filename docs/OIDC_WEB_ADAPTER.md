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

## Explicit boundaries

This adapter provides HTTP routing and local session handling, but it is not a complete consumer-facing login product. It does not render a login UI, implement MFA or provider-wide logout, revoke provider-issued access tokens, supply secret-manager integration, configure DNS/TLS/proxy headers, or perform deployment-specific security testing. The host must add its own UI, account authorization policy, logging with sensitive-field redaction, rate limits and operational monitoring. A verified OIDC subject establishes identity, not ARTA tool permissions; permissions must still be granted separately by trusted policy.

Before public deployment, test against the actual identity provider and WSGI server/proxy, review cookie and origin behavior in supported browsers, exercise backup/restore and key rotation, and obtain an independent security review. The local test suite proves the adapter's coded contract, not production readiness.
