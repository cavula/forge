# ADR 0002: Tenant isolation in PostgreSQL

Status: Accepted by ARCHITECT; QA-SECURITY review completed for M0.
Owner: ARCHITECT. Security reviewer: QA-SECURITY. Scope: M0 / WP-0.4.

Every resource belongs to an organization, including users. Identity-provider
issuer/subject pairs are unique within an organization; shared identities and membership
models can be introduced in a later migration. Organization IDs form part of
resource primary keys and foreign keys, preventing cross-tenant references.

All nine entity tables enable and force PostgreSQL row-level security. Policies
apply to reads and writes. Missing tenant context denies access. Each application
operation uses WithOrg to establish a transaction-local forge.org_id from an
authenticated, authorized context. Queries also include explicit org predicates.
The setting is not an authentication mechanism: callers with direct SQL access
can select a tenant. Therefore SQL injection prevention, credentials isolation,
and authorization at the API boundary remain required before M1 endpoints ship.

The runtime role is neither table owner nor superuser and has no BYPASSRLS,
role creation, or database creation capability. A separate owner migrates the
schema. Bootstrap creates the runtime role before goose runs. Production role
provisioning uses deployment-managed credentials rather than the Compose password.

Audit rows permit only SELECT and INSERT for the runtime role; a trigger also
rejects UPDATE, DELETE and TRUNCATE. Owners/superusers can alter schema or disable
triggers; external export and tamper evidence remain later hardening work.

Validation: tenant integration tests exercise cross-org reads, inserts, updates,
foreign keys, connection reuse, callback rollback and immutable audit records.
CI must execute these against PostgreSQL 16 using the runtime role.
