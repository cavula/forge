# ADR 0007: Reviewable contract files before initial release

Status: Accepted for M0. Explicit approval: ARCHITECT role, 2026-10-21.
Owner: ARCHITECT. Work package: WP-0.1.

## Decision

Split the unpublished `entities.proto` into one file per entity and one file per
shared enum. Regenerate Go, Connect and TypeScript outputs in each review slice.
Preserve every protobuf fully qualified name, field number, field type, JSON name,
enum value and Go package. Keep the FoundationService RPC unchanged. This approval
authorizes file layout and generated imports only; it adds no M1 behavior.

The large combined generated files cannot meet the roadmap's fewer-than-500-line
PR rule. Publish the approved initial contracts incrementally from the repository
baseline: enums before messages that import them. Each slice includes its source,
generated clients, descriptor baseline, validation and status documentation.
The one-time web lockfile exception does not cover generated contract files.

Moving declarations changes descriptor filenames and TypeScript import paths.
There is no released client to migrate: the combined files exist only on the M0
validation branch and will not be proposed as a PR. `FILE` breaking remains fully
enabled against each actual review base. Do not suppress rules to conceal the
expected filename breaks against the unpublished combined-file descriptor.

## Acceptance

Compare old and new descriptor declarations with file ownership/source locations
excluded, proving identical messages, enums and services. Run buf format/lint,
generation, Go and TypeScript tests and builds. Verify deterministic generation
and bootstrap descriptor equality. Each incremental review branch must also pass
buf breaking against its preceding slice. Report changed-line counts including
generated outputs; a work package remains pending until its CI acceptance passes.
