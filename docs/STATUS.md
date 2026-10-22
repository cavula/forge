# M0 status

Current gate: M0 in review; M1 has not started.

This first review slice records the unchanged roadmap, contributor rules and M0
scope. Runtime implementation is on the separate
[validation branch](https://github.com/cavula/forge/tree/wp-0.2-foundations);
it is not included in this documentation PR.

| WP | Owner | Dependencies | Progress and remaining acceptance |
| --- | --- | --- | --- |
| WP-0.1 | ARCHITECT | Approved contract ADR | Implemented on validation branch; contract review slices and hosted buf checks remain. |
| WP-0.2 | PLATFORM | Contracts and schema | Local clean-clone Compose checks pass; platform review slices and hosted CI remain. |
| WP-0.3 | ARCHITECT + QA-SECURITY | BRIEF | Threat model reviewed on validation branch; documentation review slice remains. |
| WP-0.4 | ARCHITECT + QA-SECURITY | Tenancy/encryption ADRs | Local migrations and RLS tests pass; schema/test review slices and hosted CI remain. |

No work package is DONE until its acceptance criteria pass in CI. The validation
branch contains detailed local evidence; those results do not establish hosted
CI success. Future PRs must remain below 500 changed lines, including generated
files and lockfiles. Next.js lockfile packaging is an unresolved review constraint.

This slice validates BRIEF byte integrity using its original attachment SHA-256.
The existing main branch's Apache-2.0 license and README are preserved.

- `go-scaffold` — PLATFORM: M0: add the Go monorepo scaffolding and review checks. Validation: format, vet, Go race tests/build, helper coverage and govulncheck; hosted CI required before review readiness.

- `tenant-isolation` — ARCHITECT + QA-SECURITY: M0: enforce PostgreSQL tenant isolation and audit immutability. Validation: PostgreSQL16 up/down/up, non-owner cross-tenant and absent-context tests; hosted CI required before review readiness.

- `security-contract-adrs` — ARCHITECT + QA-SECURITY: M0: document threat boundaries and approved contract decisions. Validation: security review and inherited Go/database CI; hosted CI required before review readiness.

- `contract-org` — ARCHITECT: M0: define the Org contract and generated clients. Validation: buf lint/format/breaking, generated-client consistency, Go and TypeScript tests; hosted CI required before review readiness.
