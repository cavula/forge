# ADR 0003: Envelope encryption for state and secrets

Status: Accepted by ARCHITECT; QA-SECURITY review completed for M0.
Owner: ARCHITECT. Security reviewer: QA-SECURITY. Scope: M0 / WP-0.4.

State and secret records reserve ciphertext, a wrapped data-encryption key,
12-byte nonce and master-key identifier. Plaintext columns are intentionally
absent. M0 defines storage boundaries only; it does not implement a crypto
service or expose read/write endpoints. Schema shape alone cannot prove encryption.

The subsequent encryption implementation must use AES-256-GCM with a fresh
random data key per object/version and unique nonce per encryption. Bind org ID,
object ID, resource kind and schema version as authenticated associated data.
Use a KMS provider or explicitly configured local master key to wrap data keys.
Keep master keys outside PostgreSQL, container images and source control. Local
keys must be mounted from protected files; no generated default production key.
Key IDs support rotation by rewrapping data keys without changing plaintext.

Never return secret values in general resource APIs or put state, plaintext,
keys or webhook credentials in logs, traces, audit event payloads or AI prompts.
Backups contain ciphertext but still require access controls and encryption.

Before M1 state or secrets ship, add encryption round-trip, wrong-tenant/AAD,
tamper rejection, secret-leak and rotation tests plus QA-SECURITY review.
A provider-neutral metadata layout makes the KMS choice reversible.
