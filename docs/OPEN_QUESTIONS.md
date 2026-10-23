# Open questions and reversible decisions

The unchanged BRIEF is authoritative. The user authorized M1 on 2026-10-22;
M2 and later milestones remain outside the current gate.

| Question | M0 choice | Follow-up |
| --- | --- | --- |
| Repository namespace? | Resolved: user selected `https://github.com/cavula/forge.git`; ADR0006 approves `github.com/cavula/forge`. Existing main history and Apache license preserved. | No namespace decision remains. |
| Who is ARCHITECT? | Assign the roadmap ARCHITECT role to the contract agent; root reviews tenancy/encryption/scope ADRs. QA-SECURITY reviews security boundaries. | Maintainers choose human approval/CODEOWNERS identities before collaboration. |
| Is User global or tenant scoped? | Tenant-local OIDC membership, composite tenant identity. | M1 may add global identities/membership links through migration/ADR. |
| Does M0 require resource CRUD or crypto? | Entity contracts/schema only; one public GetInfo RPC exercises Connect. No secret/state write paths exist. | M1 must add authenticated CRUD, actual envelope encryption and negative crypto tests. |
| Which engine is the default? | OpenTofu. Terraform is BYO; no Terraform binaries included. | Runner engine validation in M1. |
| Which migration tool? | Embedded goose SQL migrations; migration credentials isolated from runtime. | Production owner/backup/retention provisioning later. |
| Local KMS and master key format? | Reserve envelope metadata; choose AES-256-GCM and external KMS or explicitly mounted local key (ADR0003). | Select providers and test key rotation before state/secret writes. |
| Is Valkey required? | Omit optional Valkey under the authoritative BRIEF. No events yet, so no LISTEN/NOTIFY implementation needed. | The later instruction attachment requests Valkey; reconcile that additional preference before adding event delivery. |
| Must contracts use separate entity files? | The original roadmap requires nine entity definitions; merged main groups them in entities.proto. | The later attachment requests separate files. The unmerged review split is archived; future file moves require a new approved ADR and compatibility plan. |
| How much Temporal/OTel behavior in M0? | PostgreSQL-backed Temporal dev service; no workflows. HTTP OTel instrumentation only. | M1 workflows; M2 exporters/metrics/production operations. |
| PostgreSQL image patch selection? | Track `postgres:16-bookworm` in dev and CI; native validation used 16.15. | Pin production image digests and maintain patch updates before deployment. |
| Go version within 1.23+? | Pin 1.26.10 toolchain and 1.26 module floor to satisfy current dependency requirements. | Maintain security patch updates via CI. |
| Breaking checks without an existing base branch? | Check committed M0 descriptor on bootstrap; compare actual Git base SHA subsequently. | Resolved: main contains M0; subsequent changes compare against the actual base SHA. Never silently skip checks. |
| Can the <500-line PR rule fit the whole bootstrap? | PR #2 merged the combined bootstrap; superseded draft PRs #1 and #3–#8 are closed. | The user approved an exception only for web/pnpm-lock.yaml. The combined merge exceeded that scope; STATUS records this process deviation. Future PRs retain the original limit. |
| Can local validation establish clean-clone Compose and CI acceptance? | Native checks plus fresh-clone Compose startup, Docker PostgreSQL tests and both app image scans pass. | Resolved: both hosted jobs passed on merged main commit 89a41c5 in run 39674216212. M0 is merged and validated; M1 is now authorized separately. |

## M1 choices

- Security/monitoring framework: organize the existing requirements with NIST
  CSF 2.0 and the OTel signal model in CONTROLS.md. This is a reversible evidence
  baseline, not certification. Deployment profiles, telemetry backend/retention,
  alert destinations and numeric SLOs remain operator choices at M2/M6 gates.
- Operator bootstrap is insert-only per supplied new organization UUID; it does
  not require a globally empty database or disable RLS. Existing volumes need a
  reviewed backup/restore into a freshly provisioned cluster; application startup
  never performs it. Automatic review rejected changing existing database roles;
  subsequent testing found PostgreSQL's bootstrap superuser cannot be demoted.
  Validate the corrected fresh-cluster provisioning with a disposable fixture.

- API-token format: `forge_v1.<selector>.<secret>` with 128-bit random selector,
  256-bit secret and SHA-256 over the entire canonical token (ADR0010). No
  token persistence or public authentication is provided by this primitive.

- OIDC provider and initial administrator: keep issuer/client configuration
  explicit; no public auto-enrollment or request-supplied admin role. An operator
  bootstrap and verified identity-to-membership flow require their own slice.
- Existing memberships receive reader as the least privileged valid role.
  Missing membership, unspecified/unknown roles and unknown actions deny access.
  Teams group users without adding permissions (ADR0009).
- State, secrets, credentials and run approval need explicit permissions before
  exposure; ordinary metadata/resource access does not authorize them.
- No identity RPC is added by the first slice. New contracts require a new
  ARCHITECT-approved ADR; published protobuf filenames remain unchanged.

Accepted choices are reversible via a new migration or approved ADR. Plaintext
schema constraints cannot prove encryption; direct SQL credentials can select the
custom tenant setting. M0 makes neither an encryption-service nor an auth claim.

## M1 implementation choices — 2026-10-23

- Stacked helper prerequisites: use a feature integration branch containing only
  reviewed slices as the base for small dependent draft PRs. Do not merge that
  composite to main; retarget and remeasure after prerequisites merge.
- Stack CRUD configuration/revision/environment semantics are accepted in ADR0018.
  Preserve existing wire fields and use BigInt for revisions in TypeScript.
  Legacy incomplete rows need a reversible migration choice before CRUD storage;
  do not invent repository/version values or claim those rows are runnable.
- Auth records use a separate encryption domain and digest-scoped forced RLS,
  with a 1 KiB ciphertext limit. Mounted key loading rejects symlinks, including
  projected symlink mounts; operators must provide a protected regular file.
  Broader platform-specific mount support requires its own reviewed loader.
- Session expiry provenance belongs to the future opaque verified-identity helper;
  the schema alone cannot verify an issuer, subject or ID-token expiry. Routes
  remain unbound until lifecycle, CSRF, limiting and independent security gates pass.
