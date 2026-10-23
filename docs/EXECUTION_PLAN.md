# Forge: specification-driven parallel-agent delivery roadmap

Updated 2026-10-23. Owner: root coordinator; required reviewers: ARCHITECT and
QA-SECURITY for their existing gates. BRIEF.md remains verbatim and authoritative
for product scope, stack, work packages and acceptance. This plan replaces the
human-effort calendar as the execution strategy; it changes no acceptance gate.

## Planning policy

The user supplied human estimates, not mandatory durations for coding agents.
Do not repeat five weeks for M1 or six months for v1.0 as an agent forecast.
Acceleration comes from concurrent independent implementation, generated clients,
automated verification and fixing integration failures early. It does not come
from reducing scope, deferring required security or declaring partial WPs done.

M1 has a **seven-day stretch target from adopting this plan**, not a guaranteed
delivery date or a measured forecast. Check progress against that target daily;
if the gate is not met, report the remaining work and evidence, then continue.
No calendar deadline overrides acceptance. Forecast later milestones from actual
completed WPs and integration throughput, not an assumed AI speed multiplier.

M0 is complete. M1 is active. M2 and later implementation remains unauthorized
until the current milestone report and user direction. Planning future waves
does not start them. Stop and report at every milestone.

## Team and operating loop

Use the available four concurrent slots: root integrates and publishes while
up to three agents implement independent components or perform required reviews.
Rotate completed agents onto the next ready dependency. Do not wait for a PR
merge when safe independent work or an explicitly stacked PR can progress.
Only one agent owns each file at a time; root owns STATUS and integration.
Give each agent a compact task with the repository specs, owned files, inputs,
outputs and tests. Avoid duplicating long conversation histories as design truth.
Reuse repository evidence and generated contracts to reduce handoff overhead.

| Agent responsibility | Deliverable | Parallelization rule |
| --- | --- | --- |
| Coordinator / integration | Ready queue, branch bases, combined build, PR publication and evidence | Always active; unblocks the critical path and prevents duplicate work. |
| ARCHITECT / specification | Approved ADRs, precise protobuf contracts and security invariants | Works ahead of consumers; contract approval precedes proto edits. |
| CORE-BACKEND | Identity, orgs, stacks, encrypted state/secrets, VCS and transactional audit | Separate file ownership and approved interfaces permit parallel slices. |
| ORCHESTRATION | Temporal workflows, runner isolation and authorized log delivery | Develop against contract-backed activity mocks while APIs are implemented. |
| POLICY | Rego controls, embedded evaluation and saved-plan decision binding | Library/evaluator tests run before workflow wiring. |
| FRONTEND | Typed API clients, stack/run views, logs and approvals | Build against approved mocks, then prove behavior with the real server. |
| PLATFORM | Reproducible builds, dev deployment, CI, release packaging and operations | Automate feedback continuously; retain milestone-specific deployment scope. |
| QA-SECURITY | Independent negative tests, tenant/secret/runner/AI review and e2e evidence | Review sensitive slices alongside development before acceptance. |

These are rotating responsibilities, not eight simultaneous processes. Use all
available slots safely; do not imply unlimited agents or linear speed gains.

## Specification-driven feature lifecycle

1. **Specify:** extract the exact BRIEF requirement and write observable
   acceptance criteria, failure cases, tenant/secret boundaries and dependencies
   in the WP record or linked API document. State ambiguities in OPEN_QUESTIONS.
2. **Design:** ARCHITECT approves interfaces/ADRs, migrations and trust boundaries.
   Retain non-owner DB roles, authorization-derived WithOrg and explicit org
   predicates. Establish protobuf contracts and generated Go/Connect/TypeScript clients before
   consumers. Preserve compatibility and define test fixtures at the boundary.
3. **Develop:** assign bounded file ownership and implement independent consumers
   in parallel against those contracts. Integrate a working path early rather
   than accumulating disconnected helpers or postponing I/O until the end.
4. **Test:** run unit, real-I/O, negative-security and end-to-end checks at the
   appropriate scope. Bind each acceptance claim to command/CI/runtime evidence;
   repair failures immediately. Keep mandatory independent security review.
5. **Build:** produce reproducible pinned Go/web/container artifacts. Regenerate
   clients and enforce lint, compatibility, vulnerability and image scans in CI.
6. **Deploy:** prove fresh-clone Compose for M1 evaluation; add Kubernetes/Helm in
   M2 and signed release/upgrade checks in M6. Prepare reviewable deployment and
   rollback evidence. Repository merges and production deployment remain under
   user/operator control; this plan does not authorize unattended production use.
7. **Maintain:** plan regression tests, patch/vulnerability triage, backup/restore,
   observability, retention and upgrade/rollback evidence. M2/M4/M6 deliver their
   original operational requirements. Future maintenance agents use bounded
   authorized tasks and reviewed PRs; they do not silently change production.

The loop below coordinates this lifecycle across work packages.

1. Inspect authoritative repository, PR, CI and running-task state.
2. Choose the next ready WP slice and record its owner, dependencies and gate.
3. Approve concrete contracts through ARCHITECT ADRs before proto edits.
4. Implement against generated contracts; use mocks for independent consumers.
5. Run meaningful unit, I/O integration and security-negative tests immediately.
6. Obtain required independent review, fix findings, publish below-500-line PRs.
7. Verify hosted CI; mark ready only after checks pass. The user controls merges.
8. Reconcile main after merges; retarget dependent PRs and resolve conflicts
   before asking the user to review them. Do not create duplicate review PRs.
9. Update evidence and continue the next ready slice without another user prompt.

The active goal provides continuation while its runtime is available. A pause,
usage limit, missing credentials or external outage must be reported accurately;
do not describe a stopped process as continuously running. Continue independent
work when a particular task is blocked. Notify on useful outcomes or blockers.

## M1 parallel waves

The day ranges below are stretch checkpoints, not evidence of completed work.
Reviewers operate alongside implementation; integration starts in the first wave.

| Checkpoint | Concurrent work | Dependency / evidence |
| --- | --- | --- |
| Days 1–2 | CORE: WP-1.1 verified login, orgs/teams/RBAC/tokens; CORE: WP-1.3/1.8 crypto and state/secret schema; POLICY: WP-1.9 evaluator; ARCHITECT: stack/run contracts | Verified identity before tenant authority; encryption negative tests; generated contracts; policy fail-closed tests. |
| Days 2–4 | CORE: WP-1.2 stack CRUD and WP-1.3 HTTP state; ORCH: WP-1.5 workflow and WP-1.6 runner; FRONTEND: WP-1.11 views against approved mocks | Authenticated CRUD and real DB isolation; tofu init/lock contention; deterministic Temporal tests; runner isolation/egress proof. |
| Days 3–5 | CORE: WP-1.4 VCS integration and WP-1.8 cloud OIDC; ORCH: WP-1.7 live/persisted logs; POLICY: WP-1.9 workflow binding; CORE: WP-1.10 audit | Verified webhook deliveries; short-lived cloud credentials; authorized log access; exact saved-plan hash; transactional audit. |
| Days 5–7 | FRONTEND/CORE/ORCH/POLICY/QA: integrate every path; repair failure/replay/cancel/concurrency behavior; complete WP evidence | Full LocalStack MVP flow plus negative security tests and fresh-clone CI. No remaining required M1 behavior. |

These waves overlap only across safe dependencies. A UI can use approved mocks
while its server is built; public endpoints cannot bypass unfinished auth, and
an execution path cannot apply before policy/approval/state/runner gates pass.

## Complete M1 scope and exit checks

| WP | Required outcome before DONE |
| --- | --- |
| WP-1.1 | OIDC authorization-code login with PKCE/state/nonce/replay checks; org/team administration; admin/writer/reader RBAC; scoped, expiring, revocable API tokens; current membership enforcement. |
| WP-1.2 | Authenticated stack create/read/update/delete with repo, branch, path, engine, version and environment variables; tenant-negative I/O tests. |
| WP-1.3 | HTTP state backend; authenticated locking/versioning/encryption and recovery behavior; real tofu init and concurrent-apply rejection. |
| WP-1.4 | GitHub App and GitLab integrations; HMAC verification, replay handling, PR plan comments and commit statuses. |
| WP-1.5 | Temporal RunWorkflow; cancellation, timeouts, bounded retries and failure semantics proven by tests. |
| WP-1.6 | Job-pulling runner; ephemeral rootless containers, no host credentials and enforced egress policy, tested rather than assumed. |
| WP-1.7 | Authorized WebSocket logs, persisted at completion, with tenant boundaries and secret-leak protection. |
| WP-1.8 | Encrypted secret variables and short-lived OIDC cloud credentials; no static credentials by default or secret-bearing logs. |
| WP-1.9 | Embedded OPA plan evaluation; ten tested controls; deny/warn/approval enforcement bound to the saved plan; safe evaluation failures. |
| WP-1.10 | Append-only audit entries for every mutating call, committed with the mutation and tested. |
| WP-1.11 | Stacks list, run detail, live logs, plan diff and authorized approve/discard UI using the actual API. |

Every WP retains >=70% business coverage, integration tests for I/O, no secrets
in logs, applicable regenerated clients, documentation/ADRs and green CI:
lint, tests, builds, buf lint/breaking, govulncheck and image scans.
Every proposed PR stays below 500 changed lines including generated files.

Final M1 gate: push → PR plan comment → policy result → human approval → apply
to LocalStack → encrypted versioned state → matching audit entries. Verify the
combined branch and relevant PR CI; mocks and passing component tests alone do
not establish completion. Report results and remaining questions before M2.

## Later milestones: dependency-driven batches

These retain the BRIEF's full scope; their forecasts follow measured M1 delivery.

| Milestone | Concurrent batches after authorization | Exit gate |
| --- | --- | --- |
| M2 | WP-2.1/WP-2.2 dependencies/outputs and scheduled drift; WP-2.3 Kubernetes runners/Helm; WP-2.4 Ansible; WP-2.5/WP-2.6 registry/optional cost; WP-2.7 OTel/backups/retention | Production-core acceptance, integration and operational evidence for all required WPs. |
| M3 | WP-3.1 gateway and WP-3.2 MCP plus WP-3.4 eval harness first; then WP-3.3 codegen, WP-3.5 explanation, WP-3.6 UI and WP-3.7 injection defenses | >=80% benchmark prompt validity; no secrets to models; AI produces PRs and never applies. No M3 before MVP gate. |
| M4 | WP-4.1 scheduled compliance, WP-4.2 version scanner and WP-4.3 advisory/config feeds; WP-4.4 policy reevaluation; WP-4.5 upgrade PRs and WP-4.6 dashboard/exports | Outdated AWS provider produces an upgrade PR with a passing plan within one scan cycle. |
| M5 | WP-5.1 typed blueprints and WP-5.2 self-service checks; WP-5.3 CLI, WP-5.4 platform provider and WP-5.5 notifications in parallel | Each ecosystem entry point passes its authorized end-to-end flow and CI. |
| M6 | WP-6.1 load/SLO verification and WP-6.2 security review; WP-6.3 docs/runbooks and WP-6.4 signed release/SBOM/upgrade checks | Tested 500-stack/50-run load; security findings resolved; signed, upgrade-tested v1.0. |

Production readiness also retains HA control plane/Temporal/Postgres, PITR and
restore proof, SLO alerts, stuck-run/lock/state/key/DB runbooks, online key
rotation, API/webhook/AI rate limits and per-org retention/deletion. No earlier
milestone or fast target substitutes for those release requirements.

## Evidence and forecasts

STATUS.md is the current record of merged, open, local and blocked work. Report
those separately. A completed helper or PR is not a completed WP. Avoid invented
precise progress percentages; label any rough effort estimate as judgment.

At each checkpoint record completed acceptance gates, elapsed execution time,
CI/integration failures and remaining critical-path dependencies. Revise the
next delivery forecast from that evidence. If the seven-day M1 stretch target
is missed, report why and the tested remainder without silently shrinking M1.
