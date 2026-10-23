# Stack environment contract

ADR0018 approves `forge.v1.StackEnvironmentVariable` with string `name` at field 1
and string `value` at field 2. These are non-secret configuration values visible
to organization readers. Secret variables belong to WP-1.8's separate write-only
interface; this type must never carry credentials or secret material.

This first contract slice adds the type and generated Go/TypeScript descriptors.
Pinned Buf generation also runs the Connect generator; this message introduces
no RPC, service client, server handler or Stack field. Validation and protected
environment-name enforcement remain requirements for later CRUD implementation.
The type alone does not enforce those rules or prove entered text is non-secret.
Configuration values must never enter logs, audit payloads or AI requests.

Validation covers Buf lint, format, build and breaking against the actual PR base,
deterministic generation, generated Go compilation, TypeScript checking and wire/
descriptor tests. This contract slice does not complete WP-1.2 or its CI gate.
