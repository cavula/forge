# Stack configuration metadata

ADR0018 appends `environment_variables` at field 10 and uint64
`configuration_revision` at field 11 to the existing `forge.v1.Stack` message.
The original fields 1–9, Engine values, package and filename remain unchanged.

Environment entries are non-secret metadata visible to organization readers.
Secret variables and credentials require WP-1.8's separate write-only interface.
Configuration values must never appear in logs, audit payloads or AI requests.

Revision is server-assigned metadata. TypeScript clients preserve it as `bigint`;
protobuf JSON encodes uint64 as a decimal string. Never convert through JavaScript
Number: valid revisions can exceed `Number.MAX_SAFE_INTEGER`. Later Update/Delete
contracts will require the expected revision to prevent stale mutations.

This slice adds no RPC or handler. CRUD validation, authorization, revision and
non-secret enforcement remain later implementation gates. Validation covers Buf
lint/format/build/breaking, deterministic clients, Go/TypeScript compilation and
wire/descriptor tests including a revision above the safe Number range.

The Node test preloader resolves extensionless generated protobuf imports to
TypeScript. It is limited to generated source imports and leaves Buf output intact.
