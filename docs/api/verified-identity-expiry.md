# Verified identity expiry provenance

`OIDCVerifier.Verify` retains a private expiry only after provider signature,
issuer, audience/authorized-party, nonce and registered-claim checks succeed.
The required exact `exp` claim must contain one positive canonical integer of
Unix seconds and agree with the SDK-verified expiry. Quoted numbers, fractions,
decimal/exponent spellings, duplicate expiry keys, malformed values and expired
tokens return the existing generic error and the entirely zero identity.

Issuer, subject and expiry remain private and redact through formatting,
GoString, JSON, text and structured logging. There is no expiry constructor,
setter or public accessor, and no token or additional claims are retained.

The private `usableForSession(now)` guard requires a nonempty verified identity
and a nonzero expiry strictly after `now`. Zero identities and identities
reconstructed only for membership lookup fail that guard. Membership resolution
keeps its existing behavior; it does not gain session authority from an org hint.

Future session creation must use this guard and cap its database expiry at the
earlier of eight hours and the verified token expiry. A session lookup must not
invent a new token expiry or authorize renewal. No session storage, cookie,
callback or route wiring is implemented here. QA-SECURITY and CI remain gates.
