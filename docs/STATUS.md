# M0 status

Current gate: **M0 implementation complete; native validation complete;
Docker validation and image scans passed; hosted CI pending. M1 not started.**

Local container validation completed on 2026-10-21. The corrected web image
passed a second fresh-clone startup with a new database volume and a clean Git
worktree. Temporary test stacks were removed; the workspace development stack
is running at http://localhost:3000. Stop it with `make down`.

The supplied roadmap is stored byte-for-byte in BRIEF.md. The workspace was empty
and contained no preexisting code, Git history, instructions or functionality.
Repository: https://github.com/cavula/forge. The published
[wp-0.2-foundations validation branch](https://github.com/cavula/forge/tree/wp-0.2-foundations)
is based on the existing `main` commit, preserving its Apache-2.0 license and
history. Initial publication: `ca70725a924d2b5cc884ccaafb42849a73beb1ae`.
[Draft PR #1](https://github.com/cavula/forge/pull/1) contains the first 245-line
documentation slice; its roadmap-integrity CI passed. No PR contains the combined bootstrap.
Roles were explicitly assigned following the roadmap's swarm instructions.

| WP | Owner | Dependencies | Progress | Acceptance evidence / remaining gate |
| --- | --- | --- | --- | --- |
| WP-0.1 | ARCHITECT | BRIEF, approved ADR0001 | Implemented; CI pending | Nine entity contracts, public build RPC, Go/Connect/TS generated; buf lint/build/format/breaking pass, regeneration deterministic. Hosted CI required for DONE. |
| WP-0.2 | PLATFORM (root) | Contracts, schema | Implemented; hosted CI pending | Monorepo, Compose, Make, CI, Next.js, Go entrypoints, Apache-2.0. Native lint/tests/builds/smoke pass. Docker Engine validation passes: clean-clone make dev, image scans and container database tests. Hosted CI remains. |
| WP-0.3 | ARCHITECT + QA-SECURITY | BRIEF | Implemented and reviewed; CI pending | STRIDE runners/state/webhooks/AI, trust boundaries, mitigation milestones and acceptance evidence. QA reviewed schema and platform. |
| WP-0.4 | ARCHITECT + QA-SECURITY | ADR0002/0003, runtime role | Implemented; CI pending | Nine forced-RLS tables, composite references, tenant helper, append-only audit. Migration up/down/up and original isolation suite pass on PostgreSQL16.15. Final issuer/subject and bidirectional suite pass. |

Roadmap rule: a WP becomes **DONE only when its acceptance criteria pass in CI**.
Implemented does not mean CI-green. No later-milestone code has been added;
worker/runner/CLI and future modules are explicit placeholders.

## Validation

- PASS: BRIEF byte comparison against the supplied attachment.
- PASS: buf lint, format, descriptor build, breaking against initial descriptor,
  deterministic Go/Connect/TypeScript generation.
- PASS: Go vet and all command builds; tests with race detection.
- PASS: real PostgreSQL16.15 goose up, down, reapply; tenant-isolation suite using
  non-owner/NOBYPASSRLS role. Final QA rerun also passes: both tenant directions, absent-context writes, and non-owner enforcement.
- PASS: business/security helper coverage: database 87.5%, HTTP 100%, leak helper
  100% including final QA additions. The CI floor is 70% per implemented helper.
- PASS: TypeScript check, protobuf wire/secret metadata tests, Next.js production
  build, frozen lockfile install, production web vulnerability audit.
- PASS: govulncheck: no reachable vulnerabilities found.
- PASS: native HTTP smoke: readiness, Connect GetInfo JSON and production web.
- PASS: Docker Compose v2.39.4 configuration validation.
- PASS: `make dev` in the workspace and a fresh Git clone with a new volume;
  container builds, Temporal health, standalone page/JavaScript assets, migration
  rollback/reapply and all nine
  entity isolation tests against Docker PostgreSQL.
- PASS: server and corrected web image vulnerability/secret scans at HIGH/CRITICAL
  severity (Trivy 0.76.0), zero findings and no suppressions. Initial web image had
  105 package findings; ADR0005 replaces its bundled build tools and OS utilities
  with Next standalone output on a nonroot distroless Node24 runtime. Build pnpm
  updated to 10.34.5; CI scanner version aligned with local validation.
- PASS: ADR0006 aligns module/import/protobuf Go options with `github.com/cavula/forge`;
  contracts retain the same wire fields/RPCs. Generation, Go race/integration tests,
  vet/builds and TypeScript checks pass after the namespace change.
- PASS: hosted checks job in run 39621151617: generation, lint, migrations,
  tenant isolation, tests, builds, coverage, buf breaking, govulncheck and web audit.
- RETRYING: hosted Compose job could not resolve the old Trivy action tag before
  starting. Updated to verified upstream `v0.36.0`; scanner remains `v0.76.0`.
  Full acceptance requires the corrected Compose/image-scan job to pass.

## Review and publication

ARCHITECT approved initial API ADR0001; root ARCHITECT reviewed and accepted
ADRs0002–0006. QA-SECURITY reviewed isolation/encryption boundaries, threat model,
and final platform configuration. Its issuer/subject and bidirectional coverage
findings were incorporated. Encryption implementation, auth and runner security
remain future gates, without exposed M0 operations.

Do not publish this entire bootstrap as one PR. It exceeds 500 changed lines,
including generated code and lockfiles. Proposed review order:

1. BRIEF/license/role instructions and scope ADR.
2. Tenancy/encryption ADRs and schema, then helper/tests (each below 500 lines).
3. Threat model and security documentation.
4. Contract ADR/config and incremental entity contracts with generated outputs.
5. Platform services/entrypoints, web shell, Compose, then CI/docs.

Before opening PRs, split the large entity proto/generated Go file into per-entity
files in an ARCHITECT-approved ADR and arrange lockfile/tooling slices to respect
the strict 500-line limit. No generated-file exemption is assumed; no oversized
PR has been created. The combined validation branch exists to run the complete CI gate; it is not
a proposal to merge an oversized PR.

See OPEN_QUESTIONS.md for reversible choices: resolved repository namespace,
maintainer approval identities, tenant-local users, key provider, version pins,
bootstrap breaking baseline and publication slicing. Stop at M0 until its
remaining acceptance gates pass and the milestone report has been reviewed.
