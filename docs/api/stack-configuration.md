# Mutable stack configuration contract

ADR0018 approves `forge.v1.StackConfiguration` with name, repository URL, branch,
working directory, engine, engine version and non-secret environment entries at
fields 1–7 respectively. It imports the existing Engine and environment types;
Stack and its metadata remain in their established files.

The input deliberately excludes organization, ID, timestamps and configuration
revision. Authentication will establish organization authority, and the server
will assign resource metadata. This contract introduces no RPC or handler.

Later Create treats an unspecified engine as OpenTofu. Update requires explicit
engine and every mandatory field, replacing the whole configuration; an empty
environment list clears it. The message itself does not enforce ADR0018's URL,
ref, path, semantic-version or protected-name validation requirements.

Environment values are visible to organization readers and must contain no
secrets or credentials. They must never enter logs, audit payloads or AI requests.
WP-1.8 retains the separate write-only secret interface.

Validation includes pinned deterministic client generation, Buf compatibility,
Go/TypeScript compilation and protobuf/JSON wire and descriptor tests. These
contract checks do not complete authenticated CRUD or WP-1.2's CI acceptance.
