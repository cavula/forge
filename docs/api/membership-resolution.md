# Verified membership resolution

Owner: CORE-BACKEND; WP-1.1, dependent on ADR0011 and verified OIDC identities.
Status: implemented; QA-SECURITY approved the bounded slice on 2026-10-23.
This internal helper exposes no login or RPC handler.

`auth.ResolveMembership` accepts an opaque verified principal and a canonical
organization UUID hint. A short read-only transaction clears inherited tenant
context, sets verified issuer/subject context and queries that exact org,
issuer and subject. The SELECT-only users policy permits this lookup without
granting writes or access to other tenant resources. Only an existing membership
with a recognized current role may establish the subsequent `WithOrg` context.
Resolve again for each operation so deletion and demotion take effect.

Migration 00003 is additive and reversible. Tests run as the non-owner runtime
role against PostgreSQL: forged/missing hints, same subjects at different issuers,
multi-org identities, missing proof, proof-only write rejection, inherited-context
clearing and success/failure/cancellation cleanup. Migration up/down/up and race
tests pass locally; auth coverage is 96.9%, database 87.5%. `make integration`
explicitly includes both packages. CI acceptance remains required.

Browser state/PKCE, sessions, CSRF, rate limits and authorized handlers remain
separate gates; the lookup alone does not complete authentication or WP-1.1.
