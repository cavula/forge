# Browser-session persistence

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

`Lookup(ctx, credential)` accepts only canonical 32-byte raw base64url credentials.
A short non-owner read-only transaction clears unrelated contexts and selects
with an explicit credential digest and database-time expiry predicate. Its opaque
result keeps CSRF digest and expiry private and redacts every diagnostic format.
`Principal()` returns only issuer/subject with zero verified-token expiry: it can
resolve an existing membership but cannot create or renew a session. Lookup
confers no org, role or permission, and operation-time membership checks remain.

`Revoke(ctx, credential)` deletes only the matching active session and commits
`browser_session.revoked`/`success` atomically. Wrong, malformed, expired and replayed
credentials fail generically without affecting other rows. Concurrent revocations
have one winner. Event insertion, commit and cancellation failures roll deletion
back; no failure claims revocation or returns a partial principal.

`Replace(ctx, oldCredential, freshIdentity)` is a strict storage primitive. It
requires a canonical old credential naming exactly one row, active or expired,
and a fresh OIDC-derived expiry proof. It deletes under only the old digest,
explicitly clears that context, installs only an independently minted new digest,
and inserts the new session with the same verified database-time expiry cap.
`browser_session.replaced` records the actual old-row deletion and
`browser_session.created` records insertion; both success events and both row
mutations commit together before any new opaque value returns. Old identity and
expiry never establish the new session. Concurrent replacements have one winner.

Unknown, replayed or malformed old credentials fail without fallback creation,
events or other mutations. A future handler must clear a stale cookie and restart
a new login flow; `Create` remains the separate path when no old cookie exists.
This reversible strict choice implements ADR0016's previous-session deletion
without claiming a deletion that did not occur. Either event's insertion failure,
deferred commit rejection or transaction cancellation rolls deletion back and
retains the old row. Failures return no partial credential; membership lookup
proofs cannot replace sessions.

Tests reuse isolated migrated PostgreSQL databases with runtime operations under
FORCE RLS. Signed TLS identities prove expiry provenance and both caps; owner-only
fixture policies/triggers prove rollback, cancellation and context isolation.
Deferred event faults exercise commit rollback; concurrent tests use four real
connections. Lookup principals are tested for membership resolution and rejected
session renewal. The entire fixture database is dropped after each suite.
Replacement tests cover active/expired rows, fresh identity/expiry, both event
positions, commit rollback, cancellation, independent values and context switching.

Pruning, shared limiting, provider callbacks, cookies, Origin/CSRF and membership
revalidation remain separate QA/CI gates before any route exposure. No renewal or
handler is implemented, and WP-1.1/M1 remains incomplete.
