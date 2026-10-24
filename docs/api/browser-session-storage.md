# Browser session storage

Owner: CORE-BACKEND; WP-1.1, dependent on accepted ADR0016 and migration 00004.
This schema slice needs independent QA-SECURITY and hosted CI. It exposes no
route, persistence helper, cleanup role or completed authentication acceptance.

`browser_sessions` stores only UUID, unique 32-byte credential digest, nonempty
verified issuer/subject, 32-byte CSRF digest and creation/absolute-expiry times.
Database time sets creation; runtime INSERT cannot supply it. The server supplies
expiry, strictly after creation and at most eight hours later. Future helpers must
use the earlier of that limit and verified ID-token expiry; SQL cannot establish
that an issuer/subject or token expiry came from the verifier. No org, role,
permission, raw session/CSRF value or provider token is stored.

Forced RLS permits the non-owner runtime SELECT/INSERT/DELETE only for the matching
canonical lowercase hex `forge.browser_session_hash`. Other auth/tenant contexts
grant no session access, and session context grants no flow/tenant access. No
UPDATE, TRUNCATE, timestamp override or broad cleanup authority is granted.
Future helpers must clear other contexts, repeat digest/expiry predicates and
reset pooled connections. The expiry/UUID index supports separately reviewed
bounded pruning. Schema policies alone do not revoke expired credentials.

The anonymous event allowlist adds `browser_session.created`,
`browser_session.revoked` and `browser_session.replaced`. Sole outcome `success`
means the corresponding committed storage operation, never authentication success.
A future replacement transaction must delete the old credential, insert the fresh
one and record replacement atomically; this migration makes no atomicity claim.
Existing flow actions, runtime INSERT-only grants and privileged append-only
trigger remain. Downgrade preserves historical events and restores the flow-only
CHECK as NOT VALID, enforcing it on new writes without deleting audit history.
Reapply validates all history under the expanded allowlist.

Real PostgreSQL tests use `TEST_DATABASE_URL` for forge_app and
`DATABASE_URL` for the same disposable fixture's migration owner.
They prove canonical digest isolation, privilege/metadata/time constraints,
transaction-local reset and actual owner append-only enforcement. Never supply
owner credentials to application processes. Helpers, cleanup, provider-backed
browser tests and full WP-1.1/M1 acceptance remain later gates.
