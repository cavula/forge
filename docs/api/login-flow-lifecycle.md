# Server-side login-flow creation

`NewLoginFlowStore(runtimePool, dedicatedAuthFlowKey)` requires caller-supplied
runtime PostgreSQL and dedicated ADR0017 protected-file key dependencies.
No environment/default key discovery, browser routes or sessions are provided.

`Create` generates independent 32-byte state, binding, nonce and PKCE verifier,
plus independent flow/event UUIDs. It returns opaque state, binding, nonce and
S256 challenge values; `LoginFlowValue.Reveal` is the explicit protocol boundary.
Formatting, GoString, JSON, text and structured logs redact opaque values.
Only decoded-proof SHA-256 digests and encrypted canonical nonce/verifier JSON
enter `login_flows`. Database defaults enforce its ten-minute lifetime. Creation
and its allowlisted success event commit together before any value returns.

Short transactions clear inherited tenant/principal/session authority and install
both digest GUCs locally. Local settings restore preexisting session settings;
callers must avoid using session-level settings for authorization.

Tests require non-owner `TEST_DATABASE_URL` and disposable owner `DATABASE_URL`.
Owner-only temporary policies and a conditional event trigger test rollback and
mid-transaction cancellation; runtime operations retain FORCE RLS/narrow grants.
Creation tests prove encryption, nonce/S256 consistency, redaction and seeded
tenant isolation with pooled-context cleanup after commit, rollback and errors.

QA-SECURITY and CI gate this slice. Atomic consumption, limiting, pruning,
sessions, provider verification, cookies and CSRF remain exposure gates.
No browser route is bound; neither WP-1.1 nor M1 is complete.
