# Forge status

Current gate: **M1 authorized on 2026-10-22; implementation in progress.
Stop at the MVP e2e checkpoint before M2. M0 is complete and merged.**

Execution strategy: [agent-assisted roadmap](EXECUTION_PLAN.md). The user clarified
that BRIEF's durations estimate human effort. Use parallel implementation and
review with a seven-day M1 stretch target, full scope and unchanged security
gates. The target is not a measured delivery forecast. Do not repeat the original
five-week allowance as an established agent ETA; forecast from acceptance evidence.

Security and monitoring controls/evidence: [registry](CONTROLS.md), organized with
NIST CSF 2.0 and OpenTelemetry. This is not a certification or production-readiness
claim; exporters, alerts, recovery and SLOs retain their original milestone gates.

## M1 work packages

| WP | Owner | Dependencies | Progress / acceptance gate |
| --- | --- | --- | --- |
| WP-1.1 | CORE-BACKEND (root), ARCHITECT, QA-SECURITY | M0; ADR0009/0010/0011 | IN PROGRESS: merged role/membership and token primitives; OIDC verification merged with passing tests/QA. Browser login, administration and token persistence/endpoints remain. |
| WP-1.2 | CORE-BACKEND (root), contract/validation agents | WP-1.1; accepted ADR0018 | IN PROGRESS: generated configuration/read contracts and tested path/metadata/environment validation; authenticated storage and handlers remain. |
| WP-1.3 | CORE-BACKEND (root), QA-SECURITY | WP-1.1/1.2; ADR0013 | IN PROGRESS: reviewed envelope primitive published; state backend, versioning and lock contention remain. |
| WP-1.4 | CORE-BACKEND (root), QA-SECURITY | WP-1.2/1.5 | QUEUED: verified GitHub/GitLab webhooks, PR comments/statuses. |
| WP-1.5 | ORCH agent + root, ARCHITECT | Accepted ADR0019; WP-1.2/1.3/1.6 | IN PROGRESS: immutable approval/apply design accepted; structural model under test. Temporal workflow/adapters and real cancellation/retry evidence remain. |
| WP-1.6 | ORCH (root), QA-SECURITY | WP-1.5 | QUEUED: ephemeral rootless runner, no host credentials, egress tests. |
| WP-1.7 | ORCH (root) | WP-1.1/1.5/1.6 | QUEUED: authorized live logs and persistence. |
| WP-1.8 | CORE-BACKEND (root), QA-SECURITY | WP-1.1; ADR0013 | IN PROGRESS: encryption primitive reviewed; secret persistence/variables, key operations and cloud OIDC remain. |
| WP-1.9 | POLICY agent + root | Plan JSON; ADR0012/0014 | IN PROGRESS: ten starter controls merged; bounded SDK evaluator reviewed and tested; workflow/artifact/approval integration remains. |
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

API-token credential slice (ADR0010): CSPRNG selector/256-bit secret, strict
canonical parser, SHA-256 verifier binding and constant-time digest comparison.
Normal diagnostics redact tokens and verifiers. Auth race tests pass at 100%
coverage; QA-SECURITY approved the bounded primitive. Persistence, scoped expiry,
revocation, current membership enforcement and transactional audit remain gates.
No API is exposed by this slice. PR #11 merged after hosted CI checks,
Compose/image scans and roadmap integrity passed (run 39890935835).
OIDC verification slice (ADR0011): pinned go-oidc verifies HTTPS discovery/JWKS,
signature, issuer, audience, expiry, subject and required nonce. Provider calls
are bounded and redirects blocked. Verified identity is opaque and diagnostics
redact it. Real TLS/JWKS negative tests pass with auth coverage 100%; QA-SECURITY
approved after a diagnostic leak fix. Browser state/PKCE, one-use flow records,
sessions, CSRF, current membership and rate limits remain before exposing login.
OIDC verification and current-user message/client contracts are included in main
through PR #15. The older stacked PR #14 has the same message commit and is
superseded. No identity service handler is bound; browser login is unfinished.
The user authorized continuous work and independent/stacked PRs without waiting
for each merge; merges remain under user control. M1 scope and gates are intact.

Starter-policy slice (ADR0012): ARCHITECT approved ten stable deny/warn/approval
controls after semantic CIDR and malformed-unknown-mask regression fixes. Local
OPA 1.21.3 strict checks and 59 tests pass with 100% Rego coverage. Make/CI now
install the pinned checksum-verified CLI, compile strictly and enforce >=70%
coverage. PR #12 merged after hosted checks and Compose/image scans passed
(run 39947946196). Embedded SDK evaluation, resource/error limits,
trusted saved-plan binding and workflow approval enforcement remain WP-1.9 gates.

Publication note: PR #15 merged the OIDC and message slices together with 675
changed lines. The individual proposed slices were below 500, but this combined
merge exceeded the original rule. Future dependent PRs must be retargeted after
parent merges and checked against main before review; this is not a new exception.

Current review queue: PR #17 publishes verified membership lookup, SELECT-only
RLS and explicit auth integration tests (346 changed lines); PR #18 publishes
the approved current-user service/generated clients and wire tests (272 lines).
PR #14 is closed as superseded by merged #15. No identity handler is bound.
Independent QA race tests pass for auth 96.9%, database 87.5%, envelope encryption
100% and embedded policy 97.8%. ARCHITECT accepted ADR0013/0014; malformed UTF-8
policy input is rejected with a matching-hash regression test. Crypto/policy
workflow integration remains required, and neither component completes a WP.
PR #19 publishes envelope encryption and automatic internal-package coverage
enforcement (349 lines); PR #20 pins OPA SDK dependencies/design (140 lines).
PR #21 publishes the evaluator (386 lines), stacked on #20. Retarget and recheck
it after #20 merges. PRs #17/#18/#19 passed hosted checks, Compose/image scans and
roadmap integrity and are ready for review (runs 40007990052, 40008109801,
40013800582). #20/#21 remain pending hosted acceptance.
PR #22 publishes operator bootstrap and corrected fresh-cluster owner provisioning
(432 lines). ARCHITECT/QA approved ADR0015; independent real-I/O race tests pass
at 96.2% orgs coverage, including audit-failure atomic rollback. The combined local
generation/lint/tests/integration/build/breaking and discovered-package coverage
floor pass. Govulncheck found zero reachable/imported-package vulnerabilities;
the unused x/crypto/openpgp module advisory has no fixed version (GO-2026-5932).
Fresh disposable Compose PostgreSQL/Temporal, migrations up/down/up, built server
and web startup passed. Existing local volumes/roles are unchanged: automatic
review rejected modifying them, and fresh tests found bootstrap-user demotion is
unsupported. Corrected provisioning creates a separate non-superuser owner from
the start; existing clusters need operator-reviewed backup/restore.
ARCHITECT is designing browser flow/session persistence under ADR0016 while a
CORE agent implements protected mounted-key loading under proposed ADR0017.

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

## M1 implementation cycle — 2026-10-23

This dated record supersedes earlier queue snapshots; it does not mark a whole
work package complete. User merges remain separate from implementation progress.

| Scope | Owner | Dependencies | Evidence / next acceptance gate |
| --- | --- | --- | --- |
| WP-1.1 membership and identity RPC | CORE-BACKEND, ARCHITECT, QA-SECURITY | PRs #17/#18 | Both hosted checks, Compose/image scans and roadmap integrity pass; ready for review. No handler is bound. |
| WP-1.1 operator bootstrap | CORE-BACKEND, QA-SECURITY | PR #22 | Hosted CI passes; fresh-cluster non-superuser owner provisioning tested. Existing volumes unchanged. |
| WP-1.1 browser design / OIDC claims | ARCHITECT, QA-SECURITY | PR #24, ADR0016 | Ready, hosted CI passes. Signed-token tests reject noncanonical required claims and invalid authorized party. Browser routes remain unbound. |
| WP-1.1 flow persistence / encryption | CORE-BACKEND, QA-SECURITY | #25 on #17; #26 on #23 | Hosted runs 40022064937 / 40022152709 pass. Draft dependencies must merge before retargeting. |
| WP-1.1 one-use flow lifecycle | CORE-BACKEND, QA-SECURITY | Schema, auth encryption, mounted key | Create-only slice: 450 lines; consume increment: 249 changed lines. Independent PostgreSQL race tests prove replay exclusion, rollback, cancellation and redaction. Publication/integration remain. |
| WP-1.1 session persistence | CORE-BACKEND session agent, ARCHITECT | ADR0016, flow schema | IN PROGRESS: digest-scoped RLS, bounded expiry and anonymous append-only events. Independent QA and lifecycle/CSRF/limiter gates remain. |
| WP-1.2 stack contracts | CORE-BACKEND contract agent, ARCHITECT | Accepted ADR0018; auth before exposure | Environment type and additive Stack fields pass deterministic generation, real-base Buf breaking, Go/TS wire tests. Configuration/messages/service and authenticated CRUD remain. |
| WP-1.3 / 1.8 encryption | CORE-BACKEND, QA-SECURITY | #19; #23 on #19 | Both CI green; protected key loader rejects symlinks, insecure mode and malformed material. State/secret persistence and rotation remain. |
| WP-1.9 policy evaluator | POLICY, QA-SECURITY | #20; #21 on #20 | Hosted CI green, 97.8% local Go coverage. Saved-plan/workflow approval binding remains. |
| Execution / controls | PLATFORM, ARCHITECT | PR #16 | Hosted CI green; full scope and security gates preserved. Seven-day M1 target remains a stretch target. |

Stack contract increments each remain below 500 changed lines, including generated
clients. ADR0018 approves the exact increments before implementation. Revisions
use uint64/BigInt without conversion through JavaScript Number; Stack fields 1–9
and published descriptor filenames are preserved. A contract is not CRUD acceptance.

Flow helper review passed real PostgreSQL non-owner tests with pooled-context reset,
wrong-proof non-consumption, concurrent single winner, ciphertext tampering and
audit-failure rollback. The consume transaction commits before decryption, so a
failed exchange cannot reuse the same callback. No provider exchange or session
has been exposed. Auth business coverage is 95.1%; the isolated Create slice is
90.5%. New session tests use only the disposable fixture on port 55433.

Unmerged prerequisites may be assembled on a feature integration branch solely as
a testable base for small dependent draft PRs. No oversized integration PR or main
merge is authorized by this choice. After parent merges, retarget, remeasure the
actual diff and rerun CI before review. No M1 WP is DONE and the full LocalStack
push-to-apply/state/audit gate remains outstanding; stop there before M2.

## M1 integration cycle — 2026-10-23

This record supersedes earlier review-queue snapshots. No complete M1 WP or MVP
acceptance is claimed. Root coordinates integration; maintainer controls merges.

- Main includes roles, token primitives, starter policies, membership resolution,
  operator bootstrap, tenant/auth encryption and key loading, OIDC hardening,
  current-user service contracts, execution/design docs and login-flow creation.
  PRs #16/#17/#18/#19/#22/#24/#27/#30 are merged. #23/#25/#26 were closed as
  superseded after their contents landed through maintainer-created PR #34.
- PR #34 merged the feature prerequisite base as 2,124 changed lines. The proposed
  individual slices were below 500 lines, but this combined merge exceeded the
  small-PR rule. It is not an additional exception. Use individual reviewed PRs;
  integration bases are test scaffolding, not a combined merge queue.
- The corrected flow tests create/migrate/drop their own random database, proving
  actual connection selection and cleanup. This fixes CI interference from other
  packages' audit writes without weakening production grants. Create #30 is 499
  changed lines; Consume #31 is 243. Refreshed #31 and stack environment #28
  passed checks/Compose/image scans against merged main (40028923182/40028906885).
- Session schema #32, verified-expiry proof #35 and Create-only session #36 are
  separate drafts. ARCHITECT/QA approved their bounded designs. Independent real
  PostgreSQL race tests prove expiry caps, proof nonrenewal, ten-table isolation,
  redaction and rollback even when commit fails. Hosted CI and parent merges gate
  readiness; browser routes remain unbound.
- Lookup/Revoke is independently QA approved (303 changed lines, full auth 93.4%,
  session helper 91.0%). Strict atomic replacement is assigned to CORE-BACKEND;
  Origin/CSRF, shared limiting, pruning and provider exchange remain exposure gates.
- Stack validators are frozen with 100% statement coverage: path 214 added lines,
  metadata 234 and environment 266. Contracts through GetStack messages pass
  pinned deterministic generation, real-base Buf checks and 14 web tests.
  Independent slices/publication and authenticated CRUD storage remain.
- ARCHITECT accepted ADR0019 before run contract changes. ORCH owns the metadata
  model/structural transitions; typed activities, durable immutable apply binding,
  trusted runner/state adapters and Temporal acceptance remain required.

An isolated exact-main regression run uses a separate disposable PostgreSQL
database; existing development volumes/roles are not modified. M1 still needs the
real LocalStack push/plan/policy/human-approval/apply/state/audit acceptance gate.

## M1 parallel validation cycle — 2026-10-23

Root owns integration/publication; maintainer retains merges. This record
supersedes older queue snapshots without marking any M1 work package complete.

- Hosted foundations and roadmap CI pass for #32/#35/#36/#38/#39/#40.
  #20, #28, #31 and design #38 are ready; dependent drafts retain their gates.
- Strict session replacement #41 passed independent PostgreSQL race tests twice
  (auth92.9%, session90.4%, Replace88.9%). It is263 changed lines on #39; browser
  routing, Origin/CSRF, shared limiting and expiry-only pruning remain required.
- GetStack service #42 is340 lines on #40. Pinned generation, Buf/wire checks,
  Go tests/vet and fifteen web tests pass; no application handler is mounted.
- Run model/SDK #43 is454 lines on #38; independent structural QA and isolated
  race97.6%/vet/govulncheck pass. Stack path/metadata #44 is453 lines on #38;
  exact isolated race100%/vet/govulncheck pass. Environment validation #45 is266
  lines on #33 with focused race100%/vet evidence. Hosted CI gates new slices.
- ORCH produced unbound Temporal workflow/tests. Independent review reproduced
  a journal-read approval-timeout race and three metadata/evidence failures. Root
  corrected them before publication; race tests twice pass at91.1%, and independent
  deadline/evidence/admission probes pass. Real Temporal history, trusted activity
  adapters, fencing, runner quiescence and LocalStack acceptance remain unproven.
- CORE is implementing approved nullable legacy stack migration00006; existing
  configuration and timestamps are never invented. ARCHITECT accepted ADR0020
  for job-bound HTTP state capabilities, durable slots/fences, immutable encrypted
  versions and recovery. State schema reserves00007; no state route is enabled.
- Root's current-membership operation helper passes real PostgreSQL race tests
  twice, including demotion/deletion serialization; independent QA is in progress.
  Browser-boundary helpers passed their producer suite; independent review remains.

Exact merged-main5c6d872 regression passed isolated migrations up/down/up, full Go
race/vet/build/coverage and Buf checks; its temporary database was removed.
The subsequent stopped disposable PostgreSQL fixture is being replaced with a
fresh isolated project for further tests. No existing development role/volume was
modified. Full push/plan/policy/human-approval/apply/versioned-state/audit CI remains
the M1 completion gate; stop and report before M2.
