# auth

M1 begins with the role/action policy approved in ADR0009. Callers must resolve
an authenticated, current organization membership before evaluating `Allows`.
There are no login, membership administration or API-token endpoints yet.
Ordinary metadata/resource permissions do not grant state, secret, credential
or run-approval access. Unknown roles and actions deny, including for admins.

ADR0010 adds internal credential primitives: `NewToken`, `ParseToken` and
`TokenVerifier.Matches`. Only `Token.Reveal` returns plaintext for a future
one-time issuance response. Tokens/verifiers redact normal formatting and JSON.
Matching verifies a credential only; expiry, revocation, scopes and current
membership must be enforced before public authentication is exposed.

ADR0011 adds HTTPS provider-backed ID-token verification. Only verified tokens
with the expected browser-flow nonce produce an opaque `VerifiedIdentity`.
Provider requests are bounded and redirect-free; errors/diagnostics redact
identity data. Browser flow, sessions and membership resolution remain required
before exposing login. No OIDC handler is registered by this slice.
