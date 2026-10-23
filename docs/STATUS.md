# Forge status

Current gate: **M1 authorized on 2026-10-22; implementation in progress.
Stop at the MVP e2e checkpoint before M2. M0 is complete and merged.**

## M1 work packages

| WP | Owner | Dependencies | Progress / acceptance gate |
| --- | --- | --- | --- |
| WP-1.1 | CORE-BACKEND (root), ARCHITECT, QA-SECURITY | M0; ADR0009 | IN PROGRESS: role policy and isolated team membership schema. OIDC, identity administration and API tokens remain. |
| WP-1.2 | CORE-BACKEND (root) | WP-1.1; approved RPC ADR | QUEUED: authenticated stack CRUD and integration tests. |
| WP-1.3 | CORE-BACKEND (root), QA-SECURITY | WP-1.1/1.2; encryption ADR | QUEUED: tofu init, encrypted/versioned state, lock contention tests. |
| WP-1.4 | CORE-BACKEND (root), QA-SECURITY | WP-1.2/1.5 | QUEUED: verified GitHub/GitLab webhooks, PR comments/statuses. |
| WP-1.5 | ORCH (root) | Approved run contracts; WP-1.2 | QUEUED: Temporal workflow cancellation, timeouts and retries. |
| WP-1.6 | ORCH (root), QA-SECURITY | WP-1.5 | QUEUED: ephemeral rootless runner, no host credentials, egress tests. |
| WP-1.7 | ORCH (root) | WP-1.1/1.5/1.6 | QUEUED: authorized live logs and persistence. |
| WP-1.8 | CORE-BACKEND (root), QA-SECURITY | WP-1.1; encryption ADR | QUEUED: secret variables, cloud OIDC and leak tests. |
| WP-1.9 | POLICY (root) | Approved plan/policy contracts | QUEUED: embedded OPA and ten tested starter policies. |
| WP-1.10 | CORE-BACKEND (root) | Each mutating operation | QUEUED: transactional audit on every mutation. |
| WP-1.11 | FRONTEND (root) | Approved authenticated API; WP-1.2/1.5/1.7 | QUEUED: stacks, runs, logs, plan diff, approve/discard. |

First review slice: ADR0009, constrained reader/writer/admin roles, team membership
composite foreign keys and forced RLS, deny-by-default role/action policy, real
PostgreSQL isolation tests and CI coverage enforcement. No API contract change.
QA-SECURITY approved this bounded slice on 2026-10-22 with no blocking findings.
Local checks pass: PostgreSQL16 migration up/down/up and non-owner isolation;
Go race tests (auth 100%, database 87.5%, platform/testutil 100%); Go/TypeScript
lint and builds; web tests; unchanged protobuf regeneration and buf breaking;
govulncheck; rebuilt Compose `make dev` and HTTP/web smoke tests.
Hosted [CI run 39840689065](https://github.com/cavula/forge/actions/runs/39840689065)
passed checks and Compose/image scans; roadmap integrity also passed.
[PR #10](https://github.com/cavula/forge/pull/10) contains this first slice.
No M1 WP is DONE; full WP-1.1 acceptance still requires login and token flows.
Each PR remains below 500 added/deleted lines, including generated files.

M1 final gate: push → PR plan comment → policy result → approve → apply to
LocalStack → versioned state → audit entries. This flow is not implemented yet.

## M0 completion record

Local container validation completed on 2026-10-21. The corrected web image
passed a second fresh-clone startup with a new database volume and a clean Git
worktree. Temporary test stacks were removed. Use `make dev` to start the
workspace stack at http://localhost:3000 and `make down` to stop it.

The supplied roadmap is stored byte-for-byte in BRIEF.md. The workspace was empty
and contained no preexisting code, Git history, instructions or functionality.
Repository: https://github.com/cavula/forge. [PR #2](https://github.com/cavula/forge/pull/2)
merged the complete M0 implementation into `main` on 2026-10-21 at
`89a41c55081b9691f0079d96c0f788d1dda17df7`, preserving the existing Apache-2.0
license and history. [Main CI](https://github.com/cavula/forge/actions/runs/39674216212)
passed both the checks and Compose jobs; roadmap-integrity also passed.
Documentation PR #1 and alternative review-slice PRs #3–#8 were closed as
superseded by that merge. Their branches remain available as review history.
Roles were explicitly assigned following the roadmap's swarm instructions.

| WP | Owner | Dependencies | Progress | Acceptance evidence / remaining gate |
| --- | --- | --- | --- | --- |
| WP-0.1 | ARCHITECT | BRIEF, approved ADR0001 | DONE; merged | Nine entity contracts, public build RPC, Go/Connect/TS generated; hosted buf lint/build/breaking and deterministic generation pass. |
| WP-0.2 | PLATFORM (root) | Contracts, schema | DONE; merged | Monorepo, Compose, Make, CI, Next.js, Go entrypoints, Apache-2.0. Hosted lint/tests/builds, clean-clone make dev, image scans and database tests pass. |
| WP-0.3 | ARCHITECT + QA-SECURITY | BRIEF | DONE; merged | STRIDE runners/state/webhooks/AI, trust boundaries, mitigation milestones and acceptance evidence. QA reviewed schema and platform. |
| WP-0.4 | ARCHITECT + QA-SECURITY | ADR0002/0003, runtime role | DONE; merged | Nine forced-RLS tables, composite references, tenant helper, append-only audit. Migration up/down/up and original isolation suite pass on PostgreSQL16.15. Final issuer/subject and bidirectional suite pass. |

Roadmap rule: a WP becomes **DONE only when its acceptance criteria pass in CI**.
Both jobs passed on the merged main commit in
[hosted run 39674216212](https://github.com/cavula/forge/actions/runs/39674216212).
At the M0 completion gate, worker/runner/CLI and future modules were explicit
placeholders. M1 progress is tracked separately above.

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
- PASS: merged-main hosted run 39674216212, both checks and Compose jobs: generation, lint,
  migrations, tenant isolation, tests, builds, coverage, buf breaking, govulncheck,
  web audit, clean-clone make dev and both HIGH/CRITICAL image scans.
  The first Compose attempt could not resolve the old Trivy action tag; corrected
  to verified upstream `v0.36.0`, with scanner `v0.76.0` and no scan suppressions.

## Review and publication

ARCHITECT approved initial API ADR0001; root ARCHITECT reviewed and accepted
ADRs0002–0006. QA-SECURITY reviewed isolation/encryption boundaries, threat model,
and final platform configuration. Its issuer/subject and bidirectional coverage
findings were incorporated. Encryption implementation, auth and runner security
remain future gates, without exposed M0 operations.

## Publication outcome and remaining questions

The repository history records a process deviation: PR #2 merged the combined
bootstrap before the planned below-500-line review sequence was completed.
The user's one-time exception covered only web/pnpm-lock.yaml, not the full
bootstrap. This record does not extend that exception or claim the merged PR
met the small-PR rule. Future PRs retain the original limit.

The alternative contract-file split was not merged. Main retains entities.proto
and its generated clients, so published descriptor filenames/imports are unchanged.
The superseded local split is preserved on archive/m0-review-slices at commit
2508c1f; it must not be treated as an approved migration of the now-published API.
Any later contract change still requires a new ARCHITECT-approved ADR and real
base-branch breaking checks.

The original BRIEF remains the source of truth. Valkey is optional and omitted;
the roadmap requires nine entity contracts, not nine separate source files.
The later instruction attachment asks for Valkey and separate files. Those
additional preferences have not been applied to the merged foundation.

OPEN_QUESTIONS.md records remaining production choices: maintainer approval
identities, tenant-local users, key providers and version pin maintenance.
Authentication, encrypted state operations, workflows and executable runners
remain M1 or later work. M0 provides their contracts/schema/security decisions,
not their runtime implementation. The user subsequently authorized M1 above.
