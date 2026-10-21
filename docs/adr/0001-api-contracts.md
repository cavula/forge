# ADR 0001: Versioned foundation entity contracts

Status: Accepted for M0. Approval: ARCHITECT role, 2026-10-20.
Owner: ARCHITECT. Work package: WP-0.1.

## Context and decision

The roadmap requires contract-first development and ARCHITECT approval for every
change under `proto/`. This ADR approves the initial `forge.v1` entity contract,
including its enums, field numbers, and public `FoundationService.GetInfo` RPC.
The RPC returns only the build version and requires no database or tenant access.
Review found all nine requested entities,
explicit tenant ownership, and no secret/state value response fields. Future
contract changes require a new approved ADR; this is not blanket approval.

Use canonical UUID strings, protobuf timestamps, explicit unspecified enum
values, and additive fields. Never reuse deleted field numbers; reserve them.
User represents a tenant-local OIDC membership. Team membership remains a database
relationship until M1 defines its RPC contract. Org IDs in messages identify data;
they never authorize access. The application derives the active organization from
authenticated context and checks it against all resource relationships.

StateVersion and Secret expose metadata only. The HTTP state backend is a separate
M1 protocol; no state bytes, secret values, encrypted blobs, or key material belong
in these entity messages. Audit fields are bounded identifiers, not free-form
request payloads. Run statuses preserve both IaC and Ansible/drift vocabularies;
transition enforcement belongs to later workflows, not enum ordering.

M0 defines data contracts without inventing M1 CRUD RPCs. The foundation RPC
exercises Connect generation and transport with a minimal public build response.
Pinned Buf remote plugins generate Go messages, Connect stubs and TypeScript
messages. This requires access to the Buf registry during generation. Generated
files are reproducible build outputs rather than handwritten sources.

## Validation and consequences

`buf lint`, `buf build`, and `buf generate` validate syntax and generation in CI.
`buf breaking` compares against the target branch; bootstrap compares with a
checked-in initial descriptor baseline. Entity definitions alone implement no
authentication, authorization, state storage, or execution API.

The Go module namespace is provisional until a repository URL is selected.
Changing the module/import prefix requires an approved contract ADR. UUID format,
required values, field lengths, and legal transitions need application validation
when their M1 request contracts are introduced.
