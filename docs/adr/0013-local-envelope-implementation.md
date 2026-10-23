# ADR 0013: Local envelope encryption implementation

Status: Accepted by ARCHITECT role, 2026-10-23, for the primitive-only scope below;
QA-SECURITY review remains required before publication.
Owner: CORE-BACKEND. Scope: WP-1.3 / WP-1.8 encryption primitive only.

Implement ADR0003 with standard-library AES-256-GCM. Each Seal generates a fresh
256-bit data key, 12-byte data nonce and independent 12-byte wrapping nonce.
Store the wrapped key as wrapping nonce followed by authenticated ciphertext;
store data ciphertext, data nonce and configured master-key ID separately.
The master key is an explicitly supplied 32-byte value copied into private
storage. The eventual application loader must read a protected mounted file;
there is no generated default or environment-variable fallback in this module.

Authenticated context uses a domain label, length-prefixed organization ID,
resource ID, purpose and schema version. Wrapping uses a separate domain and
also authenticates the master-key ID. Unknown IDs and any failed authentication
deny decryption without returning partial plaintext. Diagnostics redact keys and
envelopes and errors contain no identity, key or payload values. Temporary data
key buffers are cleared; Go does not guarantee complete memory zeroization.

This slice does not expose endpoints, storage, KMS integration or cloud workload
credentials, and does not complete either work package. Before those ship, add
protected-file configuration, multi-key rewrapping/rotation tests and a KMS
provider, or explicitly choose the local provider under ADR0003, plus database
integration proving only ciphertext is stored and tenant authorization precedes
decryption. QA-SECURITY review and passing CI remain required gates.
