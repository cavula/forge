Forge: Open-Source IaC Orchestration Platform — Plan to Production
Oct 19, 2026 · @charan
0. How agents must use this document
• This is the single source of truth. Save as /docs/BRIEF.md in the repo.
• Never change an API contract (/proto) without an ADR in /docs/adr approved by ARCHITECT.
• Every work package (WP) has an owner role, dependencies and acceptance criteria (AC). A WP is DONE only when its AC pass in CI.
• Small PRs (<500 lines), always with tests and doc updates.
• If ambiguous: log the question in /docs/OPEN_QUESTIONS.md, choose the simplest reversible option, keep moving.
1. Mission & differentiation
Self-hostable, Apache-2.0 IaC control plane for OpenTofu (first-class), Terraform (bring-your-own binary) and Ansible: GitOps runs, state, policy, blueprints. Differentiators: (1) AI-assisted authoring grounded in live registry schemas via MCP; (2) continuous compliance that opens fix PRs automatically. Study (don't copy): Atlantis, Terrakube, OTF, Digger, Spacelift, env0.
2. Non-negotiable principles
1. AI never applies. AI output → PR → plan → policy → human approval → apply.
2. Security from day one: isolated rootless runners, OIDC short-lived cloud creds, encrypted state, append-only audit log.
3. OpenTofu default; never redistribute Terraform binaries (BSL).
4. Easy self-hosting: one docker compose up for eval, Helm for prod.
5. API-first: UI, CLI and a Terraform/OpenTofu provider are all API clients.
6. Contract-first: protobuf defines every interface before implementation.
3. Gaps fixed vs. original plan
• State backend: Terraform/OpenTofu HTTP backend protocol with locking, versioning, encryption at rest, rollback.
• Cloud credentials: OIDC workload identity for AWS/GCP/Azure; no static keys by default.
• Secrets: envelope encryption (KMS or local master key); write-only, masked in logs.
• Audit log: who/what/when/which stack, append-only, exportable.
• Stack dependencies: output sharing and downstream triggers.
• Real drift detection: scheduled plan -refresh-only, separate from version scanning.
• Cost estimation: optional Infracost on plans.
• Private module registry: official module registry protocol.
• Ansible lifecycle: own state machine; inventories; --check --diff preview (labelled best-effort); per-host history.
• Observability: OpenTelemetry traces/metrics, structured logs, health/readiness endpoints.
• Data lifecycle: migrations (goose/atlas), backups, retention.
• AI safety: registry content treated as untrusted (prompt injection), secret redaction before LLM calls, model/provider recorded per generation, local-only mode.
• AI quality: eval harness — generated code must pass validate/lint/policy; pass rate tracked per model.
• Testing: unit, integration (testcontainers), e2e on LocalStack + kind.
• Multi-tenancy: org isolation enforced in DB queries (row-level security) and tested.
4. Tech stack (decided)
Go 1.23+, Connect-RPC + protobuf (buf), PostgreSQL 16, Temporal, Valkey (optional — Postgres LISTEN/NOTIFY fallback in Compose mode), embedded OPA (Go SDK), Next.js + TypeScript, Docker/Kubernetes runners, OpenTelemetry, official MCP Go SDK. Reuse existing MCP servers (e.g. HashiCorp terraform-mcp-server); build only missing ones (OpenTofu, Ansible Galaxy).
5. Repository layout (monorepo)
• /proto — API contracts
• /cmd/server — control plane
• /cmd/worker — Temporal workers
• /cmd/runner — runner agent
• /cmd/forgectl — CLI
• /internal/{auth,orgs,stacks,runs,state,vcs,policy,secrets,audit,ai,mcp,compliance,registry,blueprints}
• /web — Next.js UI
• /policies — built-in Rego library + tests
• /deploy/{compose,helm}
• /e2e — end-to-end tests
• /docs/{BRIEF.md,adr,OPEN_QUESTIONS.md,STATUS.md,api}
6. Agent roles
• ARCHITECT: BRIEF, ADRs, proto contracts, cross-module review.
• CORE-BACKEND: auth, orgs, RBAC, stacks, state, secrets, audit, VCS.
• ORCHESTRATION: Temporal workflows, runner agent, log streaming.
• POLICY: OPA integration, Rego library, policy tests.
• AI: provider gateway, MCP clients/servers, codegen, eval harness.
• FRONTEND: dashboard, live logs, approvals, AI authoring, compliance views.
• PLATFORM: CI/CD, Compose, Helm, observability, releases.
• QA-SECURITY: e2e, threat model, isolation, secret-leak and injection tests. Mandatory reviewer for auth, secrets, state, runners, AI.
7. Run state machines
IaC (Tofu/Terraform): QUEUED → PREPARING → PLANNING → POLICY_CHECK → NEEDS_APPROVAL → APPLYING → FINISHED | FAILED | DISCARDED | CANCELED. Auto-approve allowed only if policy says so. Ansible: QUEUED → PREPARING → PREVIEW (check/diff) → POLICY_CHECK → NEEDS_APPROVAL → EXECUTING → FINISHED | FAILED | PARTIAL | CANCELED. Drift: SCHEDULED → REFRESHING → DRIFT_FOUND | CLEAN → (optional) reconcile run.
8. Milestones & work packages
M0 — Foundations (week 1)
• WP-0.1 ARCHITECT: proto for Org, User, Team, Stack, Run, StateVersion, Policy, Secret, AuditEvent. AC: buf lint + buf breaking in CI.
• WP-0.2 PLATFORM: monorepo, CI (lint/test/build/govulncheck), Compose (Postgres, Temporal). AC: make dev works from clean clone.
• WP-0.3 ARCHITECT + QA-SEC: STRIDE threat model for runners, state, webhooks, AI.
• WP-0.4 ARCHITECT: DB schema + migrations; ADRs for tenancy and encryption.
M1 — Core loop / MVP (weeks 2–6)
• WP-1.1 CORE: OIDC login, orgs, teams, RBAC (admin/writer/reader), API tokens.
• WP-1.2 CORE: stack CRUD (repo, branch, path, engine, version, env vars).
• WP-1.3 CORE: HTTP state backend with locking/versioning/encryption. AC: tofu init works; concurrent applies blocked.
• WP-1.4 CORE: GitHub App + GitLab webhooks (HMAC), PR plan comments, commit statuses.
• WP-1.5 ORCH: RunWorkflow with cancel, timeouts, retries.
• WP-1.6 ORCH: runner agent — pull jobs, ephemeral rootless containers, no host creds, egress policy.
• WP-1.7 ORCH: live logs via WebSocket; persisted on completion.
• WP-1.8 CORE: secret variables + OIDC cloud credentials.
• WP-1.9 POLICY: OPA on plan JSON (deny/warn/approve rules); 10 starter policies with tests.
• WP-1.10 CORE: audit log on all mutating calls.
• WP-1.11 FRONTEND: stacks list, run detail, live logs, plan diff, approve/discard.
• MVP AC (e2e): push → PR plan comment → policy result → approve → apply to LocalStack → state versioned → audit entries present.
M2 — Production-grade core (weeks 7–10)
• WP-2.1 Stack dependencies + output sharing.
• WP-2.2 Scheduled drift detection + notifications.
• WP-2.3 Kubernetes runner mode + Helm chart.
• WP-2.4 Ansible engine (inventories, preview, per-host history).
• WP-2.5 Private module registry.
• WP-2.6 Infracost integration (optional).
• WP-2.7 OpenTelemetry, backups, retention jobs.
M3 — AI layer (weeks 11–14)
• WP-3.1 AI gateway: AIProvider interface (OpenAI, Anthropic, OpenAI-compatible: Ollama, vLLM); per-org config; secret redaction; usage/cost tracking.
• WP-3.2 MCP: reuse Terraform registry server; build OpenTofu and Ansible Galaxy servers; cache in Postgres.
• WP-3.3 Codegen pipeline: prompt + MCP context → code → validate/lint/policy → self-repair (max 3) → PR. Never apply. AC: ≥80% of benchmark prompts pass.
• WP-3.4 Eval harness: fixed benchmark (VPC, EKS, encrypted S3, RDS, Ansible nginx role…); nightly scores per model for validity, policy pass, token cost.
• WP-3.5 AI explain: plan explanation, policy-failure explanation, drift summary.
• WP-3.6 FRONTEND: AI authoring UI — prompt, diff preview, create PR.
• WP-3.7 QA-SEC: prompt-injection suite (poisoned READMEs/registry text); prove no secrets reach LLMs.
M4 — Continuous compliance (weeks 15–18)
• WP-4.1 ComplianceWorkflow (Temporal schedule per org, configurable).
• WP-4.2 Version scanner: pinned providers/modules/collections vs. latest; semver classification.
• WP-4.3 Vulnerability feeds: OSV + GitHub Advisories; Checkov/Trivy config scans.
• WP-4.4 Policy re-evaluation of all stacks when policies change.
• WP-4.5 Auto-PR bot: grouped, rate-limited upgrade PRs with attached plan and AI changelog summary.
• WP-4.6 Compliance dashboard: per-stack score, findings, trends; CSV/SARIF export.
• AC: outdated AWS provider → upgrade PR with passing plan within one scan cycle.
M5 — Blueprints & ecosystem (weeks 19–22)
• WP-5.1 Blueprint catalogue with typed inputs introspected from module variables / role defaults.
• WP-5.2 Self-service stack creation with policy pre-checks.
• WP-5.3 forgectl CLI (login, stacks, runs, logs, approve, local plan).
• WP-5.4 Terraform/OpenTofu provider for the platform itself.
• WP-5.5 Notifications: Slack, Teams, email, webhooks.
M6 — Hardening & v1.0 (weeks 23–26)
• WP-6.1 Load test: 500 stacks, 50 concurrent runs; targets for p95 queue time and log latency.
• WP-6.2 Security review: runner escape, RBAC bypass, SSRF via webhooks/MCP, cross-tenant state access.
• WP-6.3 Docs site: quick start, architecture, policy cookbook, AI setup (cloud + local), upgrades.
• WP-6.4 Release: cosign-signed images, SBOMs, semver, changelog, upgrade tests.
9. Production readiness checklist
• HA: multiple control-plane replicas, Temporal HA, Postgres with replicas and PITR backups.
• SLOs defined (API availability, run queue time, log latency) with alerts.
• Runbooks for: stuck runs, lock recovery, state rollback, key rotation, DB restore.
• Key rotation for master key, VCS tokens, AI keys without downtime.
• Rate limits on API, webhooks, AI calls.
• Data retention and deletion per org (GDPR-friendly).
10. Definition of done (every WP)
• Unit tests (≥70% on business logic) + integration tests for I/O.
• No secrets in logs (enforced by test helper).
• Proto updated, clients regenerated.
• Docs updated; ADR for any design decision.
• CI green: lint, tests, buf breaking, govulncheck, image scan.
11. Swarm coordination protocol
• ARCHITECT completes M0 before anyone else starts.
• Claim a WP by branching wp-X.Y-short-name and noting it in /docs/STATUS.md.
• Build against generated stubs/mocks so backend and frontend run in parallel.
• Update STATUS.md each cycle: done / in progress / blocked + reason.
• Conflicts resolved by ARCHITECT via ADR.
• Hard gate: no M3+ work until MVP e2e passes. Stop and report at each milestone.
12. Risks & mitigations
• Scope creep → milestone gates.
• Variable AI quality → eval harness decides supported models.
• Terraform licensing → OpenTofu default, BYO Terraform.
• Ops complexity → minimal Compose mode.
• Runner security → rootless, optional gVisor/Kata, no privileged mode, egress allow-lists.
• Ansible preview unreliability → clearly labelled, approval still required.
13. First instructions to the swarm
1. ARCHITECT: repo layout, BRIEF.md, proto (WP-0.1), threat model (WP-0.3), schema (WP-0.4).
2. PLATFORM: CI + make dev (WP-0.2).
3. After M0 merges: CORE, ORCH, POLICY, FRONTEND start M1 in parallel.
4. Stop at the MVP e2e checkpoint and report before continuing.