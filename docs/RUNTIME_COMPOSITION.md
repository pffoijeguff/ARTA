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
remote JWKS rotation, encrypted storage, and security certification are not provided. The HMAC
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
the ID token through `OidcJwksAuthenticator`; and binds the verified ID token to the original
nonce. The token response is size-bounded, and refresh tokens are rejected until a protected
refresh-token lifecycle exists.

The application must register the exact HTTPS redirect URI with its identity provider, configure
the authorization and token endpoints from trusted provider metadata, and configure the JWKS
authenticator's issuer and audience to match that provider and client ID. The client intentionally
does not accept a client secret. It keeps pending transactions in process memory, so production
deployments with multiple workers need sticky routing or a shared, protected, TTL-bound transaction
store. It is not an HTTP callback server, browser session manager, MFA system, logout/revocation
service, or full product login UI. The host app must validate its own browser session/cookie policy
and must not log access tokens or callback codes. The returned principal has an empty scope set because
standard OIDC ID tokens establish identity and do not, by themselves, grant ARTA tool permissions.
Do not pass the ID token as a scoped tool-access token; provision tool permissions separately through
a trusted authorization policy or a separately verified access token.

Example:

```python
from arta import OidcAuthorizationCodeClient, OidcJwksAuthenticator

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
)
start = login.begin_login()
# Redirect the browser to start.authorization_url.
# In the registered callback, pass the received code and state to:
result = login.complete_login(code=callback_code, state=callback_state)
# Only after success should the host app establish its own protected session.
```

No live identity-provider credentials are included in the repository; provider registration,
MFA policy, production callback hosting, browser cookie controls, and deployment testing remain
operator/application responsibilities.
