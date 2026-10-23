# Security and monitoring control evidence

Owner: root coordinator and QA-SECURITY. Scope: the unchanged BRIEF milestones.
Use this registry to connect requirements, implementation and verification.
An approved design or passing component test does not establish product readiness.

## Baseline and review

Use [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
as a reversible organizing baseline for cybersecurity outcomes. Forge's concrete
controls come from its STRIDE threat model, ADRs and BRIEF acceptance criteria.
This is an implementation/evidence mapping, not a certification or a claim of
complete framework coverage. A deployment-specific profile remains an operator
decision. No additional compliance target was specified by the user.

| Outcome | Owner / gate | Existing evidence | Remaining verification |
| --- | --- | --- | --- |
| Governance and inventory | ARCHITECT / every WP | Versioned BRIEF, ADR approvals, STATUS ownership/dependencies, reviewed PRs and CI | Maintain evidence as components integrate; explicit release decision at each milestone. |
| Tenant and identity protection | CORE + QA / WP-1.1 | Forced RLS/non-owner tests, role policy, token primitive, OIDC verifier; reviewed membership lookup | Browser login/session/CSRF/replay limits, administration and scoped token persistence/endpoints. |
| State and secret protection | CORE + QA / WP-1.3/1.8 | Ciphertext schema and reviewed AES-GCM envelope component with tamper/context tests | Protected key loading/rotation, authorized ciphertext storage, real HTTP backend locks, cloud OIDC and leak tests. |
| Execution and change protection | ORCH + POLICY + QA / WP-1.4–1.6/1.9 | Ten starter policies in CI; reviewed bounded embedded evaluator | Webhook verification, saved binary-plan/approval binding, Temporal recovery and isolated rootless/egress tests. |
| Detection and audit | CORE + PLATFORM / WP-1.7/1.10, M2/M6 | Append-only audit schema, no-secret helper, HTTP instrumentation and health/readiness tests | Transactional audit on every mutation; authorized logs, exported telemetry, alerts and delivery-failure tests. |
| Response and recovery | PLATFORM + QA / M2/M6 | Migration rollback/reapply CI, documented milestone gates | Restore/PITR, lock/state/key runbooks, rotation, retention, failure drills, measured SLOs and load tests. |

STATUS.md and each PR's hosted CI links provide the dated acceptance record.
Mandatory QA review applies to authentication, state, secrets, runners and AI.
Every mutation must preserve authorization-derived tenant context, explicit org
predicates and atomic audit. AI remains PR-only and cannot apply infrastructure.

## Monitoring implementation contract

Use the decided [OpenTelemetry signals](https://opentelemetry.io/docs/concepts/signals/)
model for traces, metrics and structured diagnostic events. Instrumentation is
distinct from exporting, collecting, alerting and responding; each needs proof.
Current HTTP instrumentation has no configured production exporter or alerting.

| Signal / control | Milestone and owner | Required evidence before acceptance |
| --- | --- | --- |
| Liveness and dependency readiness | Existing platform; extend with M1 dependencies | Failure injection returns bounded generic readiness failures; liveness does not disclose configuration. |
| API latency/error rate and auth denial | M2 PLATFORM; M1 endpoints preserve safe errors | Exported test signals, bounded labels and useful thresholds; no bearer tokens, issuer subjects or payloads. |
| Run queue/activity/retry/cancel and runner health | M1 behavior; M2 telemetry / ORCH | Deterministic workflow failure tests, then correlated signals and alert delivery tests. |
| State locks/storage and policy failures | M1 behavior; M2 telemetry / CORE/POLICY | Contention/tamper/fail-closed tests; count failures without state, secret or plan values in telemetry. |
| Live-log delivery and audit persistence | M1 behavior; M2 telemetry / CORE/ORCH | Tenant authorization/leak tests and transactional rollback proof; bounded telemetry for delivery failures. |
| Collector availability, alert routing and retention | M2 PLATFORM | Collector outage/recovery, retry/buffering limits, access controls and retention/deletion tests. |
| Availability, queue-time and log-latency SLOs | M6 PLATFORM/QA | Operator-approved numeric targets, dashboards, alert/runbook links and 500-stack/50-run load evidence. |

Validate attribute allowlists and cardinality; do not attach raw URLs, plans,
state, code, secrets or provider tokens to spans/logs/metrics. Do not use tenant
or resource identifiers as unbounded metric labels. Correlation must retain
access controls; audit events remain the authoritative mutation record.

No monitoring backend, alert destination, retention duration or numeric SLO is
silently selected here. OPEN_QUESTIONS tracks these reversible deployment choices.
Implementation follows the original M1/M2/M6 gates; this registry moves none.
