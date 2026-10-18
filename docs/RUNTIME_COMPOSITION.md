# Secure runtime composition

`SecureRuntime` is the composition root for ARTA's security-sensitive command path. It wires
JWT verification, scoped approval issuance, action-bound HMAC attestations, SQLite persistence,
the AuthorityKernel, the ToolGateway, the Bubblewrap adapter, and the evidence-aware MissionRunner.

## Security properties
- The only registered tool is the configured sandbox command tool; plans containing another tool are rejected.
- Approval issuance requires a valid externally issued JWT with `arta:approve` and
  `arta:approve:sandbox.run`, plus any operator-configured extra scopes.
- Approval is bound to the exact JSON arguments, expires within a bounded interval, is persisted,
  and is consumed atomically by MissionRunner before execution.
- argv is passed as data rather than interpolated into a host shell.
- Bubblewrap preflight must establish isolation or execution fails closed.

## Important limits
The end-to-end tests replace the sandbox runner with a test double. They validate composition,
scope enforcement, argument binding, and replay prevention; they do **not** prove kernel-level
isolation. The opt-in real-host Bubblewrap test remains a release gate. Token issuance, MFA,
remote JWKS rotation for the approval JWT key ring, and security certification are not provided. The HMAC
key and identity configuration must be managed outside the repository and SQLite database.


## OIDC JWKS key discovery and rotation

The `OidcJwksAuthenticator` implements the same verified-principal contract as `JwtPrincipalAuthenticator` and can be passed directly to `SecureRuntime` and `TrustedApprovalService` when an operator has a trusted OIDC issuer and its HTTPS JWKS endpoint. The composition path is covered by `tests/test_oidc_runtime.py`. It accepts only a
configured HTTPS URL, refuses redirects, applies a request timeout and 1 MiB response limit,
requires public signing keys with explicit supported asymmetric algorithms, rejects duplicate
key IDs/private JWK material, and caches keys for a bounded interval. An unknown `kid` causes
one forced refresh to support normal key rotation. The token's `iss`, `aud`, time claims,
lifetime and scopes are still validated by the existing principal authenticator.

Example (configure values from the identity provider's trusted operator documentation; never
take the URL, issuer, audience, or key configuration from a token or model output):

```python
from arta import OidcJwksAuthenticator, SecureRuntime

authenticator = OidcJwksAuthenticator(
    jwks_url="https://identity.example.com/.well-known/jwks.json",
    issuer="https://identity.example.com/",
    audience="arta-runtime",
    cache_ttl_seconds=300,
    timeout_seconds=3,
)
# Pass authenticator to SecureRuntime with the separately provisioned approval HMAC key,
# SQLite store, BubblewrapSandbox, and explicit required scopes.
```

This component fetches verification keys; it does **not** implement interactive OIDC login,
authorization-code/PKCE, client registration, MFA, logout, or immediate session revocation.
A provider must issue the JWTs, and operators remain responsible for issuer/audience correctness,
network egress policy, key lifecycle monitoring, secret management and deployment tests. Key
removal becomes visible after the cache expires unless an operator forces a refresh/restarts the
service. This is a key-discovery adapter, not an identity-provider product or security certification.


## Public-client OIDC login with Authorization Code + PKCE

`OidcAuthorizationCodeClient` adds the protocol client primitives for a server-side application
registered as a public client: it creates a cryptographically random state, nonce and PKCE
verifier; sends an S256 challenge to a fixed HTTPS authorization endpoint; consumes each pending
state once; exchanges the code only at a fixed HTTPS token endpoint without redirects; validates
the ID token through `OidcJwksAuthenticator`; binds the verified ID token to the original nonce, and requires a per-transaction browser-binding cookie so an attacker cannot complete a login flow initiated in another browser. The token response is size-bounded, and refresh tokens are rejected until a protected
refresh-token lifecycle exists.

The application must register the exact HTTPS redirect URI with its identity provider, configure
the authorization and token endpoints from trusted provider metadata, and configure the JWKS
authenticator's issuer and audience to match that provider and client ID. The client intentionally
does not accept a client secret. It also binds each transaction to a per-state, high-entropy browser cookie. A callback without the matching cookie cannot consume the transaction, preventing a login started in another browser from being replayed into this browser. By default it keeps pending transactions in process memory, suitable only for single-process use. For a shared deployment, inject EncryptedSQLitePendingLoginStore, which encrypts the verifier and nonce with AES-256-GCM and atomically consumes state inside a SQLite write transaction. Configure the same operator-managed 32-byte key on every worker using a protected secret manager; protect the database directory, backups and WAL files, and rotate keys deliberately because rotation invalidates outstanding logins. A shared filesystem must provide SQLite's required locking semantics. The store fails closed on wrong keys, corruption, expiry, and replay. It is not an HTTP callback server, browser session manager, MFA system, logout/revocation
service, or full product login UI. The host app must set the returned binding cookie as Secure, HttpOnly, SameSite=Lax, host-only, and short-lived; on callback it must read the cookie named by login.browser_binding_cookie_name(callback_state), pass its value to complete_login, and clear it. This browser binding prevents cross-browser login CSRF when the host follows the cookie contract. The host must also use TLS and must not log access tokens, callback codes, state values, or binding cookies. The returned principal has an empty scope set because
standard OIDC ID tokens establish identity and do not, by themselves, grant ARTA tool permissions.
Do not pass the ID token as a scoped tool-access token; provision tool permissions separately through
a trusted authorization policy or a separately verified access token.

Example:

```python
from arta import EncryptedSQLitePendingLoginStore, OidcAuthorizationCodeClient, OidcJwksAuthenticator

verifier = OidcJwksAuthenticator(
    jwks_url="https://identity.example.com/.well-known/jwks.json",
    issuer="https://identity.example.com/",
    audience="arta-web",  # must match the registered OIDC client ID
)
login = OidcAuthorizationCodeClient(
    authorization_endpoint="https://identity.example.com/authorize",
    token_endpoint="https://identity.example.com/token",
    client_id="arta-web",
    redirect_uri="https://app.example.com/oidc/callback",
    authenticator=verifier,
    pending_store=EncryptedSQLitePendingLoginStore(
        "private/oidc-transactions.sqlite3",
        encryption_key=load_32_byte_key_from_secret_manager(),
    ),
)
start = login.begin_login()
# load_32_byte_key_from_secret_manager() is an application-provided secret-manager adapter.
# Set this cookie on the response before redirecting. Use a host-only cookie with:
# Secure=True, HttpOnly=True, SameSite="Lax", Path="/", Max-Age=start.expires_in_seconds.
set_cookie(
    name=start.browser_binding_cookie_name,
    value=start.browser_binding_cookie_value,
    secure=True,
    httponly=True,
    samesite="Lax",
    path="/",
    max_age=start.expires_in_seconds,
)
# Redirect the browser to start.authorization_url.
# In the callback, find the per-state cookie and pass it to the client:
cookie_name = login.browser_binding_cookie_name(callback_state)
binding_cookie = request.cookies.get(cookie_name)
result = login.complete_login(
    code=callback_code,
    state=callback_state,
    browser_binding=binding_cookie,
)
# Clear that cookie in the callback response after processing.
# Only after success should the host app establish its own protected session.
```

No live identity-provider credentials are included in the repository; provider registration,
MFA policy, production callback hosting, browser cookie integration, provider configuration, and deployment testing remain
operator/application responsibilities.


## Opaque server-side OIDC sessions and revocation

The optional `SQLiteOidcSessionStore` provides server-side session primitives after the application has validated a login result. It creates cryptographically random opaque session tokens, stores only a SHA-256 digest of each token, encrypts the identity subject with AES-256-GCM, enforces a bounded TTL, and supports immediate revocation on subsequent validation checks for one token or all sessions belonging to a subject.

Use a separate, operator-managed 32-byte key for this session store; do not reuse the PKCE transaction-store key or the approval HMAC key. Store keys in a secret manager and protect the SQLite directory, WAL files and backups. Key rotation invalidates sessions. The subject must come from a successfully verified `OidcLoginResult.principal`, never from a callback query parameter or client-supplied identity field.

Example integration boundary:

```python
from arta import SQLiteOidcSessionStore

# Run only after login.complete_login(code=..., state=...) succeeded.
sessions = SQLiteOidcSessionStore(
    "private/oidc-sessions.sqlite3",
    encryption_key=load_separate_32_byte_session_key(),
)
session = sessions.create_session(result.principal.subject, ttl_seconds=3600)
# Set session.token in a host-managed cookie using Secure, HttpOnly and an appropriate
# SameSite policy; never place it in a URL or log it.
# On each authenticated request: sessions.validate_session(cookie_token)
# On logout: sessions.revoke_session(cookie_token)
# On account-wide logout: sessions.revoke_all_sessions(result.principal.subject)
```

The application-provided key loader and HTTP/cookie handling above are integration placeholders, not functions supplied by ARTA. Revocation makes future store validations fail; it cannot cancel a request that already passed authentication. This store does not implement an HTTP callback route, cookie middleware, CSRF defenses, MFA, provider-side token revocation, global identity-provider logout, or UI. It also does not automatically revoke access tokens issued by the identity provider. Deployment tests must cover the actual web framework, cookie policy, proxy/TLS setup and identity-provider configuration.
