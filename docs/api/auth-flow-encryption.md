# Auth-flow encryption dependency

ADR0016 authorizes this pre-tenant primitive; no route or persistence is wired.
The caller supplies `AuthFlowContext{FlowID, Version: 1}` from its trusted
server-generated lowercase canonical UUID. The API fixes the purpose to
`forge/auth/login-flow/v1`; callers cannot supply an org, tenant context or purpose.
Existing tenant state/secret envelope semantics remain unchanged.

An operator must provision a **dedicated** auth master key and explicit unique
key ID, then load it with ADR0017's `LoadLocalKeyFile` and pass that dependency to
`NewAuthFlowKey`. The constructor copies private key storage. This API cannot
prove whether operators reused key material: dedicated provisioning is an explicit
caller/operator boundary. There is no auth raw-key/environment/default fallback.

`Seal` creates a fresh 32-byte DEK plus independent 12-byte data/wrapping nonces.
Both AES-256-GCM AAD domains bind the flow UUID, fixed purpose and version;
wrapping also binds the key ID. `Envelope` retains the existing metadata layout.
Only an exact matching key/context authenticates. Unknown IDs, key loss, corruption
or authentication failure require a new login; no partial plaintext is returned.
Temporary DEKs are cleared, subject to Go's limits on complete memory zeroization.
Contexts, keys and envelopes redact formatting, JSON and structured logging.

Reversible choice: accept binary payloads from zero through **1024 bytes**,
including encoding. This conservatively accommodates a 32-byte nonce and PKCE
verifier together as binary or canonical base64url JSON; callers must still
validate that future payload schema. Decryption rejects oversized ciphertext
before allocating plaintext. This primitive does not define serialization,
perform authorization, rotate keys or persist provider credentials.

Independent ARCHITECT/QA review and hosted CI gate publication. Protected-key
configuration must pass its separate gate before any browser route runs. Flow
consumption, expiry, session minting and the full WP-1.1/M1 gates remain pending.
