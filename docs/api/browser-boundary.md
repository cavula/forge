# Production browser-boundary primitives

Owner: CORE-BACKEND; WP-1.1; dependencies: ADR0016 and session lookup.
These helpers are unbound and require independent QA-SECURITY and hosted CI.
`NewBrowserBoundary` accepts a configured HTTPS origin without path, query,
userinfo or fragment and the exact `<origin>/auth/callback`. Origin checks require
one exact non-null `Origin`; Host/proxy headers never establish configuration.
Loopback development mode remains deferred.
Cookie parsing uses an 8 KiB aggregate field budget including separators, a
reversible resource bound. Session, flow and CSRF cookies require canonical 32-byte raw
base64url values; duplicates, quotes and malformed credential cookies fail with a
generic error. Opaque values use existing LoginFlowValue diagnostic redaction.
Opaque Set-Cookie values use fixed host-only `__Host-` names, Secure, Path=/ and absolute
expiry. Reveal them only at the response boundary. Session/flow cookies are HttpOnly/Lax; CSRF is readable/Strict. Write session
cookies only after persistence and deletion cookies only after committed logout.
Flow cookies require actual persisted database expiry; LoginFlowStart does not yet
return it, so flow wiring is gated until corrected. Never guess application time.
`ValidateMutation` accepts POST/PUT/PATCH/DELETE with exact Origin and no mixed
Authorization header. A live Lookup result binds the same session credential and
canonical CSRF cookie/header using constant-time digest and raw-value comparisons.
Lookup retains its credential digest privately; its diagnostics remain redacted.
Membership/role locking, handlers, callbacks, CORS, limiting and pruning remain
separate gates. These primitives do not complete browser login, WP-1.1 or M1.
