# Forge STRIDE threat model

Owner: ARCHITECT + QA-SECURITY. Scope: WP-0.3, M0 foundations.

M0 delivers schema isolation, contracts, local development scaffolding and this
review. Runners, state HTTP endpoints, webhook ingestion and AI are not operational
in M0. Controls below are requirements for their owning milestones, not claims of
implemented protection. Do not deploy the development environment as production.

## Assets and trust boundaries

Assets: organization data, state and outputs (which may contain credentials),
secret values and encryption keys, cloud identities, source code and plans,
approvals, signed webhook payloads, audit history and AI prompts/responses.

Boundaries:

1. Internet/browser/VCS → authenticated control plane. Client identifiers and
   webhook content are untrusted; verified identity must determine organization.
2. Control plane → PostgreSQL. Organization context is transaction-local; the
   application role must not own tables or hold BYPASSRLS/superuser privileges.
   RLS supplements explicit organization predicates and tenant-scoped foreign keys.
3. Control plane/Temporal → ephemeral runner → cloud and source dependencies.
   Repository code, providers and runner reports are hostile inputs. Runners must
   not receive database credentials or control-plane master keys.
4. State/secret storage → key provider. Ciphertext and wrapped data keys may be
   stored together; master keys belong outside the database and backups.
5. AI gateway → MCP/registry/model provider → generated PR. Registry text and
   model output are untrusted data; neither conveys authorization to execute.

Local PostgreSQL and Temporal administrative access is trusted for development
only. RLS cannot constrain superusers or a compromised database administrator.
A compromised host/key provider remains outside the protection of database RLS.

## Threat register

S = spoofing; T = tampering; R = repudiation; I = information disclosure;
D = denial of service; E = elevation of privilege.

| Surface | STRIDE | Threat | Required mitigation / owning milestone | Evidence required before enablement |
| --- | --- | --- | --- | --- |
| Runners | S, E | Forged runner takes another org's job or cloud identity | M1: authenticated runner enrollment, run-bound short-lived identity and server-derived org; OIDC audience/subject checks | Reject wrong org, expired token and wrong audience |
| Runners | T, E | Hostile IaC/provider escapes or alters approved plan | M1: ephemeral rootless containers, no privileged mode/host mounts/host creds; immutable plan digest bound to approval | Isolation/escape probes; reject modified plan; cancellation cleanup |
| Runners | I | Plan, environment or logs leak credentials | M1: minimal per-run secrets, scoped cloud identity, structured redaction, restricted artifact access and egress | Canary secret absent from logs/errors/artifacts; deny cross-org downloads |
| Runners | D, R | Infinite run, forged completion, disputed apply | M1: timeouts, bounded resources/logs, authenticated results, actor/run/plan audit linkage | Timeout/cancel/retry tests and immutable execution audit |
| State | S, E | User-controlled org/stack ID bypasses tenant boundary | M0: FORCE RLS, explicit org query filters, tenant-scoped references; M1: authenticated membership/RBAC | Real PostgreSQL tests reject cross-org reads/writes, including connection reuse |
| State | T, D | Concurrent apply or replay overwrites state | M1: transactional lock ownership, version checks and atomic state version writes | Concurrent lock/write tests, stale owner rejected, rollback preserved |
| State | I | Plaintext state or keys exposed through DB/backups | M0: encryption ADR/schema; M1: authenticated envelope encryption with org/stack/version binding, external master key, TLS | Ciphertext at rest; tamper/wrong-context decrypt rejection; restore/rotation exercise |
| State | R, T | State mutation or audit record erased | M0: append-only application audit role; M1: audit each mutation with identity/version; M2: exports/backups | Runtime role cannot update/delete audit; failed mutations do not leave success audit |
| Webhooks | S, T | Forged or replayed push initiates privileged run | M1: raw-body HMAC verification, constant-time comparison, delivery deduplication, repository-installation/org binding | Invalid/missing signature, modified body, replay and wrong installation rejected |
| Webhooks | E, I | Payload URL causes SSRF or credential disclosure | M1: use configured VCS endpoints, URL allowlist, block metadata/private destinations and redirect bypasses | SSRF tests include redirects, DNS rebinding and cloud metadata addresses |
| Webhooks | D, R | Flood or duplicate delivery overwhelms jobs; origin disputed | M1: bounded body/queue, rate limits, idempotency and delivery-to-run audit | Oversize/rate-limit tests; duplicate delivery creates at most one run |
| AI | S, T, E | Poisoned registry/MCP text instructs model to apply or steal data | M3: untrusted-context separation, bounded tools, validated MCP destinations, PR-only output; no apply capability | Prompt-injection suite proves no execution/approval bypass |
| AI | I | Prompt, tool result or telemetry sends secrets across org/provider boundary | M3: per-org provider settings, pre-egress redaction, least-context retrieval, local-only mode | Canary-secret egress tests, cross-org context denial and local-only network test |
| AI | D, R | Unbounded repair loop/cost or unattributed unsafe output | M3: maximum three repairs, token/rate/time budgets, record model/provider and evaluation results | Budget tests; generated output must validate/lint/pass policy before PR |

## Security acceptance and residual risks

M0 acceptance requires PostgreSQL 16 integration tests run as a non-owner,
non-BYPASSRLS role. Exercise reads and writes in both directions, absent tenant
context, foreign-key tenant mismatch, transaction rollback and pooled connection
reuse. Check append-only audit permissions. Schema constraints do not substitute
for endpoint authentication, membership checks or encryption implementation.

QA-SECURITY reviews auth, secrets, state, runners and AI before their milestones
are enabled. M1 must preserve the rule: AI output → PR → plan → policy → human
approval → apply. Policy-authorized auto-approval must never grant AI an apply
capability. M3 cannot start until the MVP e2e gate passes.

Open risks: development credentials and exposed local services are unsuitable for
shared hosts; administrators can bypass database controls; dependency code can
exfiltrate any credentials intentionally supplied to its runner. Production runner
sandboxing/egress, retention, backups, key rotation and incident runbooks remain
milestone work. Track unresolved choices in OPEN_QUESTIONS.md, with owners and
validation results in STATUS.md.
