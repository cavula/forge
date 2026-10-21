# Open questions and reversible decisions

M0 decisions are bounded by the unchanged BRIEF. No M1 feature is authorized here.

| Question | M0 choice | Follow-up |
| --- | --- | --- |
| Repository namespace? | Resolved: user selected `https://github.com/cavula/forge.git`; ADR0006 approves `github.com/cavula/forge`. Existing main history and Apache license preserved. | No namespace decision remains. |
| Who is ARCHITECT? | Assign the roadmap ARCHITECT role to the contract agent; root reviews tenancy/encryption/scope ADRs. QA-SECURITY reviews security boundaries. | Maintainers choose human approval/CODEOWNERS identities before collaboration. |
| Is User global or tenant scoped? | Tenant-local OIDC membership, composite tenant identity. | M1 may add global identities/membership links through migration/ADR. |
| Does M0 require resource CRUD or crypto? | Entity contracts/schema only; one public GetInfo RPC exercises Connect. No secret/state write paths exist. | M1 must add authenticated CRUD, actual envelope encryption and negative crypto tests. |
| Which engine is the default? | OpenTofu. Terraform is BYO; no Terraform binaries included. | Runner engine validation in M1. |
| Which migration tool? | Embedded goose SQL migrations; migration credentials isolated from runtime. | Production owner/backup/retention provisioning later. |
| Local KMS and master key format? | Reserve envelope metadata; choose AES-256-GCM and external KMS or explicitly mounted local key (ADR0003). | Select providers and test key rotation before state/secret writes. |
| Is Valkey required? | Omit optional Valkey. No events yet, so no LISTEN/NOTIFY implementation needed. | Introduce event delivery when workflows exist. |
| How much Temporal/OTel behavior in M0? | PostgreSQL-backed Temporal dev service; no workflows. HTTP OTel instrumentation only. | M1 workflows; M2 exporters/metrics/production operations. |
| PostgreSQL image patch selection? | Track `postgres:16-bookworm` in dev and CI; native validation used 16.15. | Pin production image digests and maintain patch updates before deployment. |
| Go version within 1.23+? | Pin 1.26.10 toolchain and 1.26 module floor to satisfy current dependency requirements. | Maintain security patch updates via CI. |
| Breaking checks without an existing base branch? | Check committed M0 descriptor on bootstrap; compare actual Git base SHA subsequently. | Publish a default branch; never silently skip breaking checks. |
| Can the <500-line PR rule fit the whole bootstrap? | Draft PR #1 adds the first 245-line documentation slice. Continue publishing the implementation in small review slices. | The combined validation branch runs CI without a PR. Future contract splits fit; adding Next alone adds 540 lockfile lines. A legitimate smaller packaging change or explicit user exception is needed before a web bootstrap PR; no exception was assumed. |
| Can local validation establish clean-clone Compose and CI acceptance? | Native checks plus fresh-clone Compose startup, Docker PostgreSQL tests and both app image scans pass. | Resolved: both hosted jobs passed in run 39644071200 at commit 2708af4. Small review PRs and merges remain before M1. |

Accepted choices are reversible via a new migration or approved ADR. Plaintext
schema constraints cannot prove encryption; direct SQL credentials can select the
custom tenant setting. M0 makes neither an encryption-service nor an auth claim.
