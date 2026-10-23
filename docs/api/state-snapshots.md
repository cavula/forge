# Exact-byte state snapshot validation

Owner: CORE-BACKEND; WP-1.3; approved design: ADR0020. This helper is unbound;
independent QA-SECURITY and hosted CI remain required before publication/exposure.

ValidateSnapshot accepts at most 16 MiB of valid UTF-8 without BOM, one complete
JSON object, version exactly 4, canonical decimal serial 0..MaxInt64 and a canonical
lowercase nonzero UUID lineage. All three case-sensitive metadata fields are
required. Root aliases under Unicode EqualFold (including ſerial) are rejected;
other unknown root and nested provider names stay unchanged. Integer fractions,
exponents, signs and leading zeroes are rejected.
Unknown members are scanned and retained, without interpreting provider values.
Decoded duplicate keys fail at every object depth, including escaped aliases.
Root counts as container depth 1; 128 container levels are accepted, 129 rejected.
Trailing JSON whitespace is retained; trailing tokens/data are rejected.

Snapshot owns a defensive exact-byte copy. Metadata returns a copy of version,
serial, lineage, server-computed SHA-256 and byte count. CloneBytes explicitly
reveals a fresh plaintext copy for a later authorized encryption/HTTP boundary.
Mutating input, returned bytes or metadata cannot change the retained snapshot.
Zero/nil snapshots fail closed. Snapshot and metadata formatting, JSON/text
marshalling and structured logging redact their contents; errors never echo input.
Callers must not concurrently mutate input during validation. Bound plaintext
lifetimes and clear boundary copies where practical; Go cannot guarantee full
memory zeroization, including JSON decoder buffers.

This slice proves syntax/metadata and exact-byte identity only. It supplies no
tenant/job authority, cross-version serial/lineage replay rule, encryption, DB,
lock/fence, HTTP limit enforcement or endpoint. Those remain ADR0020's separately
reviewed implementation and real-runner acceptance gates. No client checksum is
trusted, and a valid snapshot does not prove an infrastructure apply succeeded.
