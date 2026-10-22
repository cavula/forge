# ADR 0006: Confirmed repository namespace

Status: Accepted for M0. Approval: ARCHITECT role, 2026-10-21.
Owner: ARCHITECT. Work package: WP-0.1; publication dependency of WP-0.2.

## Context and decision

The user selected `https://github.com/cavula/forge.git`. Replace the provisional
`github.com/forge-iac/forge` Go module, imports and protobuf `go_package` options
with `github.com/cavula/forge`. Regenerate Go, Connect and TypeScript clients and
the bootstrap descriptor before first publication. This deliberately changes Go
source import paths, but preserves protobuf package names, field numbers, wire
types, JSON names, enum values and the FoundationService RPC path. There is no
published client or previous release to migrate.

This approval covers only the repository namespace, not file reorganization,
semantic changes, additional fields, or new RPCs. Subsequent contract changes
require a new ADR. The existing `entities.proto` and `foundation.proto` retain
their filenames, declaration order and comments.

## Review and compatibility

The roadmap counts generated files and lockfiles toward the strict fewer-than-500
changed-line PR limit. This preparation targets a hosted CI validation branch;
it does not create an oversized PR. A temporary generation experiment found that
per-declaration source files could make complete generated message/enum units
reviewable within the limit. That reorganization remains deferred and requires a
separate approved ADR. Incremental dependencies alone do not resolve the web
lockfile limit: adding Next to the other current dependencies adds 540 lines.
Record an agreed review plan before proposing PRs; do not hide or minify files.

Changing `go_package` is observable in descriptors and generated source imports.
Comparison with the saved unpublished descriptor reports precisely the two
approved Go package option changes. No breaking rules are suppressed. Regenerate
the bootstrap descriptor with the confirmed namespace and use actual base-branch
compatibility checks once a published contract baseline exists. No published API
is replaced.

## Acceptance

Run `buf format --diff --exit-code`, `buf lint`, descriptor build, generation,
Go tests/builds, TypeScript checks and contract tests. Regeneration must be
deterministic; compare the final descriptor against its committed baseline.
Compare old and new descriptors with only Go options and source locations
excluded, verifying that all wire contracts remain identical. This decision does
not start M1 or waive the hosted CI milestone gate.
