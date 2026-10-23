# ADR 0009: M1 identity and authorization foundation

Status: Accepted. Approval: ARCHITECT role, 2026-10-22.
Owner: CORE-BACKEND. Required reviewer: QA-SECURITY. Scope: WP-1.1 first slice.

The user authorized M1 after M0 merged. This slice establishes persisted roles,
team membership isolation and an internal authorization policy. It does not
complete WP-1.1 or expose login, identity administration or token endpoints.
No protobuf changes are authorized by this ADR; new contracts require approval.

Persist each organization-local user's role as admin, writer or reader, with a
database constraint and reader default for existing memberships. Reader is the
least privileged valid membership, not permission to create a membership or a
replacement for authentication. Unspecified and unknown protobuf Role values,
missing membership and unknown actions deny access, including for admin.
Reader permits ordinary metadata reads; writer adds ordinary resource writes;
admin adds identity administration. Sensitive state, secrets, credentials and
run approval need explicit action decisions in later slices before exposure.

Add team_memberships keyed by organization, team and user with composite foreign
keys to organization-local teams and users. Enable and FORCE RLS, retaining the
non-owner runtime role. Teams group users and confer no additional permissions
in this slice. Every application query includes an organization predicate and
runs in WithOrg with transaction-local context derived from authorization.

Later OIDC login must verify signature, configured issuer, audience, expiry and
flow protections before resolving issuer/subject to an existing membership.
Request-supplied organization IDs are selection hints, never authorization.
An explicit operator bootstrap may establish the first administrator; public
login must never create an admin or self-elevate. Team or identity mutations
require authorization and audit entries in the same transaction.

API tokens must be random, scoped, expiring and revocable, shown once and stored
only as a one-way verifier. Token authorization must respect current membership
and revocation. Credentials, identity payloads and tokens must not enter logs.
These are later implementation gates, not claims of functionality in this slice.

Acceptance: role/action matrix unit tests; PostgreSQL migration down/up and
runtime-role integration tests for defaults, constraints, tenant RLS and foreign
keys; QA-SECURITY review; existing CI remains green. WP-1.1 stays IN PROGRESS
until OIDC, orgs, teams, RBAC and tokens have their own passing CI evidence.
