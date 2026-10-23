# ADR 0016: Browser login flows and opaque sessions

Status: Accepted by ARCHITECT role, 2026-10-23, for the concrete design below.
Owner: CORE-BACKEND. Scope: WP-1.1 within M1; refines ADR0011. Independent
QA-SECURITY review gates each sensitive implementation slice and route exposure.
This ADR adds no protobuf declarations, handlers or completed acceptance claims.

## Configured protocol boundary

Use the existing pinned go-oidc verifier and oauth2 client for authorization-code
flow with S256 PKCE, query-mode response and `openid` scope. Support one explicitly
configured issuer/client per installation in this slice. Provider discovery,
authorization/token/JWKS URLs must be HTTPS with no userinfo or fragment; the
issuer must match exactly. Validate provider endpoints at startup, disable HTTP
redirect following and cap outbound timeouts/body sizes. Operator-configured
client credentials come from protected files and never reach browser responses.
Do not persist provider access/refresh/ID tokens or request offline access.

Configure one external origin and exact registered callback
`<origin>/auth/callback`; never derive either from Host/Forwarded headers. UI,
auth routes and RPCs share that origin through deployment routing. Production
requires HTTPS. Explicit loopback development mode may use HTTP and distinct
non-prefixed cookies; it cannot activate from a request or production default.

The following HTTP protocol routes are approved for later implementation only:

| Route | Contract |
| --- | --- |
| `POST /auth/login` | Same-origin browser initiation, empty body, no org/role/issuer/return URL input. Creates one flow and returns a 303 to the configured provider. |
| `GET /auth/callback` | Accepts exactly one bounded state and either one code or one provider error; rejects duplicate/ambiguous parameters, unexpected methods and fragment/form-post flows. |
| `POST /auth/logout` | Requires the session's Origin/CSRF checks; atomically deletes that session and records its revocation, then clears its cookies. |

Callback success redirects to fixed `/`; failure redirects to fixed
`/login?error=authentication_failed`. No provider messages or caller-selected
redirect is reflected. Auth responses use `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`; the callback renders no page or third-party asset.
Cap callback query size at 8 KiB, code at 4 KiB, and accept state/cookies only as
canonical 32-byte unpadded base64url values. Reject duplicate credential cookies.
Proxy/access logs and HTTP tracing must omit callback queries and credential
headers before these routes are enabled, including failures and redirects.

## Single-use browser flow

Generate independent CSPRNG 32-byte state, browser-binding, nonce and PKCE
verifier values for each attempt. Send state, nonce and the verifier's S256
challenge to the configured provider; only the browser-binding value goes into
the flow cookie. Store SHA-256 digests of state and binding, never their raw
values. Keep nonce and PKCE verifier together in an encrypted server-side payload.
The flow expires after ten minutes by database time. A new start replaces the
browser's binding cookie; an older parallel attempt may fail and must restart.

Use a new domain-separated auth-flow envelope API rather than inventing an org
for `secrets.Context`. Preserve existing tenant-envelope semantics unchanged.
`AuthFlowContext{FlowID, Version:1}` binds a server-generated UUID and fixed
`forge/auth/login-flow/v1` purpose; data/wrapping AAD domains are distinct from
tenant state/secrets. Retain ADR0013's fresh DEK/nonces and generic errors. Use a
dedicated auth-flow master key through the protected mounted-file loader in
ADR0017, with explicit key ID and no raw-key environment/default fallback. No
browser route may run before that dependency passes QA/CI. Replacing the key may
invalidate in-flight flows; unknown key IDs/tamper require a new login. This does
not authorize tenant state/secret key rotation or weaken their separate gates.

After checking syntax and browser binding, atomically execute
`DELETE ... WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now()
RETURNING ...` with matching RLS context and commit consumption before decrypting
or contacting the token endpoint. Wrong state/binding must not burn a valid flow.
Exactly one concurrent callback can consume it; every subsequent callback fails.
An exchange, decryption or verification failure leaves it consumed, including
provider errors. Restart login rather than retrying a code with retained verifier.
Exchange using the configured callback and consumed PKCE verifier; require an ID
token verified by the existing verifier against the consumed expected nonce.
Extend verification to reject multiple audiences without an `azp` equal to the
configured client, and any present mismatched `azp`; test this explicitly rather
than assuming the SDK does it. If an authorization response supplies `iss`, it
must exactly match the configured issuer before exchange. Provider metadata and
request parameters cannot select a second issuer or token endpoint.
Require exact case-sensitive registered claim names and reject case-folded
aliases for issuer, subject, audience, expiry, nonce and optional iat/nbf. The SDK's
JSON struct decoding must not substitute or shadow those claims.

## Tenant-neutral storage and RLS

Create separate auth tables, owned by the migration role with ENABLE/FORCE RLS;
`forge_app` remains NOSUPERUSER/NOBYPASSRLS and owns none of them:

| Table | Persisted data and narrow authority |
| --- | --- |
| `login_flows` | Server UUID, unique 32-byte state hash, 32-byte binding hash, creation/expiry times, encrypted payload/ciphertext nonce/wrapped DEK/key ID. No org or identity. |
| `browser_sessions` | Server UUID, unique 32-byte credential hash, verified issuer/subject, 32-byte CSRF hash, creation/absolute-expiry times. No provider token, role, permission or tenant authority. |
| `auth_security_events` | Server event UUID, database timestamp, allowlisted action/outcome only. No credentials, hashes, provider messages, identities or request metadata. |

Auth helpers use short transactions that clear org, verified-principal and other
auth lookup contexts before setting transaction-local `forge.login_state_hash`
plus `forge.login_binding_hash`, or `forge.browser_session_hash`. Decode only
canonical digest encodings. Flow SELECT/DELETE/INSERT policies require both
matching digests; session policies require its matching digest. SQL repeats those
explicit predicates and checks expiry. Grant only required SELECT/INSERT/DELETE,
not UPDATE; no broad SELECT, SECURITY DEFINER bypass, or auth-context tenant RLS
policy is introduced. Claimed state/session values never set `forge.org_id`.

Keep anonymous credential-lifecycle events separate from tenant audit: flow
creation/consumption and session creation/revocation record an allowlisted event
atomically with their mutation. Runtime may INSERT events but cannot SELECT,
UPDATE, DELETE or TRUNCATE them; reuse append-only enforcement. Tenant resource
mutations still require their existing actor/org audit event in the same
transaction. A generic failed login is a safe security outcome, not tenant audit
authority or permission to include its raw inputs.

Expired rows require bounded periodic pruning before public exposure. Use a
separate non-owner/NOBYPASSRLS cleanup role with only SELECT on UUID/expiry columns
and DELETE of expired flow/session rows under forced RLS. Use indexed expiry/UUID
ordering and a CTE limited to 100 UUIDs per transaction; test bounded batches.
No active-row or credential column access, tenant grants or audit deletion.
Do not put owner credentials in server/worker processes or add a broad cleanup
policy to `forge_app`.

## Session, tenant authorization and CSRF

On verified callback mint fresh independent 32-byte session and CSRF values.
Store only their SHA-256 verifiers plus the verified principal. Session expiry is
the earlier of eight hours and the verified ID-token expiry; extend the private
verified-identity representation to carry that verified expiry, not caller data.
No refresh/renewal is implemented: expiry requires login. Persist the new session
before Set-Cookie. In the same transaction delete any presented previous session
by its digest and record replacement: install the parsed old digest context for
its explicit DELETE, clear it, then install the newly minted digest for INSERT,
all in that one transaction. No policy admits both rows or grants broad access.
Failed persistence sets no new credential.
This prevents adopting a caller-chosen session or preserving a replaced credential.

Production session and flow cookies are host-only `__Host-forge-session` and
`__Host-forge-login`, Secure, HttpOnly, Path=/, SameSite=Lax, with matching expiry.
Use `__Host-forge-csrf` with Secure, Path=/, SameSite=Strict and no HttpOnly so the
same-origin UI can send its value in `X-Forge-CSRF`. Require exact configured
Origin (reject absent/null), matching CSRF cookie/header and constant-time match
against the stored CSRF digest on every cookie-authenticated mutation, including
logout. Login initiation requires exact Origin; callback instead requires the
consumed flow proof. No credentialed cross-origin CORS or GET mutation is allowed.

Session lookup returns only a verified principal. `X-Forge-Org-ID` remains a hint:
call the accepted membership resolver, then re-read matching issuer/subject/user,
current membership and current role inside the operation's WithOrg transaction
before authorizing it. Hold `FOR SHARE` on that membership row through the
operation's commit so role UPDATE/deletion serializes with authorization; a plain
SELECT or `FOR KEY SHARE` is insufficient. Unknown/expired/revoked sessions and missing
membership fail closed. Logout deletes the server record before clearing cookies;
database failure cannot claim successful revocation. API-token persistence,
scopes and precedence are a separate ADR/slice; reject ambiguous mixed credentials
until that interaction is explicitly approved.

## Abuse bounds and acceptance slices

Before exposure require a shared, bounded auth limiter at login start, callback
before consumption/exchange, and credential lookup. Fail closed on limiter
failure. Its contract separately limits global work and trusted client-source
attempts without unbounded attacker-selected keys; trust forwarded addresses only
through an explicit proxy allowlist. Thresholds/backend are a separate reversible
implementation choice that needs QA review and real concurrent exhaustion tests
before wiring. Never log source/credential/identity values to diagnose denial.

Publish independently reviewed slices, each strictly below 500 changed lines
including tests/docs/generated files; split further when measured diff requires:

1. Auth-flow domain/key dependency and negative crypto/config/leak tests; retain
   no handlers and preserve tenant-envelope behavior.
2. Flow schema/RLS/atomic consume plus real PostgreSQL concurrency, wrong-binding,
   expiry, rollback and pooled-context reset tests.
3. Session/event schema and opaque persistence/logout helpers plus real PostgreSQL
   expiry/revocation, replacement, append-only and privilege tests.
4. Expiry-only cleanup and limiter contracts/implementation with negative role,
   resource/exhaustion and multi-connection tests.
5. Login initiation, then callback/exchange as separate unbound handler slices;
   use TLS IdP fixtures to prove PKCE, nonce, issuer/audience/signature/expiry,
   replay, malicious redirects, provider failures and secret-safe diagnostics.
6. Cookie/Origin/CSRF/session middleware and logout; prove cookie attributes,
   duplicate rejection, cross-origin failures and current-membership/demotion
   races; only then bind protocol routes after independent QA and hosted CI.

Real DB tests must assert FORCE RLS/non-ownership, absent/wrong digest denial,
auth-only context inability to read tenant resources, explicit predicates and
reset after commit/rollback/cancellation/reused connections. Corrupt envelopes,
wrong keys, expired flows and simultaneous callbacks must never mint a session.
Business coverage stays >=70%, I/O tests use the non-owner runtime role, and leak
checks cover errors, formatting, logs, traces, redirects and cookies in fixtures.
Provider-backed browser e2e plus the full WP-1.1/M1 gates remain required; no helper
or accepted ADR completes a WP, advances M2, or authorizes production deployment.

References: [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[OIDC code-flow validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[PostgreSQL 16 RLS](https://www.postgresql.org/docs/16/ddl-rowsecurity.html).
