# Server-side login-flow lifecycle

`NewLoginFlowStore(runtimePool, dedicatedAuthFlowKey)` requires caller-supplied
dependencies. Load the dedicated key through ADR0017; no environment or default
key selection occurs here. These helpers expose no browser routes or sessions.

`Create` generates independent 32-byte state, binding, nonce and PKCE verifier,
plus independent flow/event UUIDs. It returns opaque state, binding, nonce and
S256 challenge values; `LoginFlowValue.Reveal` is the explicit protocol boundary.
Formatting, GoString, JSON, text and structured logs redact opaque values.
Only decoded-proof SHA-256 digests and the encrypted nonce/verifier JSON enter
`login_flows`. Database defaults enforce its ten-minute lifetime. Creation and
its allowlisted success event commit together before any outbound value returns.
The returned `ExpiresAt` is read from the inserted row, not calculated from the
application clock. Browser wiring uses it for the binding cookie's deadline.

`Consume` accepts canonical unpadded 32-byte base64url proofs. A short transaction
clears inherited tenant/principal/session authority, installs both digest GUCs
locally and deletes with both explicit digest predicates plus database-time expiry.
Deletion and its success event commit before decryption. A wrong proof preserves
the valid flow; replay and concurrent losers fail. Tamper, key mismatch or invalid
payload consumes the row and returns only `ErrLoginFlow`, without partial values.
Payloads require exactly the generated canonical JSON schema, key spelling/order
and two canonical 43-character nonce/verifier values; unknown/duplicate keys fail.
Transactions never persist lookup context; transaction-local settings restore any
preexisting session settings, which callers must avoid using for authorization.

Real PostgreSQL tests require non-owner `TEST_DATABASE_URL` and disposable owner
`DATABASE_URL` fixtures; each test creates/drops its own database. Temporary policies and conditional fault
triggers verify expiry, corruption, event rollback and cancellation; runtime
operations retain FORCE RLS and their narrow grants. No owner dependency enters
the helper. Tests also cover actual concurrent consumption and tenant isolation.

QA-SECURITY review and CI gate each slice. Limiting, pruning, session persistence,
provider-backed callback verification, cookies and CSRF remain exposure gates;
these helpers complete neither WP-1.1 nor the M1 checkpoint.
