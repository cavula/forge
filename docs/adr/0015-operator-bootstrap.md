# ADR 0015: Explicit operator organization bootstrap

Status: Accepted by ARCHITECT, 2026-10-23, including corrected role provisioning;
implementation and provisioning approved by QA-SECURITY, 2026-10-23. CI pending.
Owner: CORE-BACKEND. Scope: WP-1.1, within M1; refines accepted ADR0011.

Use a dedicated `cmd/bootstrap` process with separately supplied owner credentials.
Require the authenticated session role itself to own orgs/users/audit_events, with
NOSUPERUSER/NOBYPASSRLS and enabled, forced RLS. Never escalate roles or disable
RLS. Its trusted operator configuration supplies the WithOrg transaction context.
Insert organization, exact known HTTPS issuer/subject admin binding and an audit
event together; existing IDs fail without overwrites. No provider discovery,
automatic enrollment, runtime startup invocation or public handler is introduced.

Interpret "initial organization" as provisioning each new supplied org UUID; do
not require an empty database. This reversible interpretation supports later
operator provisioning without global RLS bypass or a new singleton schema.
The operator must independently establish the principal's exact issuer/subject;
the command performs no identity verification. IDs are canonical nonzero UUIDs;
bounded text rejects controls and surrounding whitespace. Errors are generic,
success prints only the org UUID, and audit contains only action/IDs. Keep owner
credentials out of server/worker environments. See the [operator guide](../api/operator-bootstrap.md).

For fresh development Compose/CI clusters, initialize PostgreSQL as the separate
forge_maintenance superuser, then create forge_owner with NOSUPERUSER/NOBYPASSRLS,
NOCREATEROLE/NOREPLICATION and CREATEDB for Temporal auto-setup; transfer the forge
database ownership to forge_owner. Provision forge_app separately for runtime.
Maintenance credentials stay out of application/bootstrap processes. The initdb
bootstrap superuser cannot be demoted; existing volumes require operator review
of backup/restore into a fresh cluster with the separate owner. Never discard data
or automatically rewrite existing roles. Production provisions independent credentials.
