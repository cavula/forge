# Initial browser-session persistence

`NewBrowserSessionStore(runtimePool)` requires an explicitly supplied non-owner
runtime PostgreSQL pool. It does not discover owner credentials or configuration.
`Create(ctx, VerifiedIdentity)` accepts only an opaque proof carrying expiry from
successful OIDC verification. Zero identities, membership-only identities and
expired proofs return `ErrBrowserSession` without credentials or storage changes.

Creation generates independent 32-byte session/CSRF values and independent
session/event UUIDs. Only SHA-256 digests plus verified issuer/subject enter the
session row. Provider tokens, orgs, roles and permissions are never persisted.
The database chooses expiry as the earlier of `now()+8 hours` and the verified
ID-token expiry, requires a future value, and returns it as `ExpiresAt`.

Short transactions clear inherited tenant, principal and login-flow contexts
before installing only the new session digest locally. Session insertion and
`browser_session.created`/`success` commit together before returning any values;
the event describes the storage mutation. Failures return no partial result.
`Credential` and `CSRF` reuse `LoginFlowValue`: private storage, explicit `Reveal`
at the cookie boundary, and redacted formatting, GoString, JSON, text and logging.
Transaction-local settings restore preexisting session settings; callers must
avoid session-level authorization settings.

Tests reuse isolated migrated PostgreSQL databases with runtime operations under
FORCE RLS. Signed TLS identities prove expiry provenance and both caps; owner-only
fixture policies/triggers prove rollback, cancellation and context isolation.

This slice creates an initial session only. Lookup, revocation, atomic replacement,
pruning, shared limiting, provider callbacks, cookies, Origin/CSRF and membership
revalidation remain separate QA/CI gates before any route exposure. No renewal or
handler is implemented, and WP-1.1/M1 remains incomplete.
