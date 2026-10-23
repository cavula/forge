# Current membership in resource transactions

`auth.WithMembership` accepts an existing verifier/session identity proof and an
organization selection hint. Initial resolution identifies an existing member;
the operation re-reads that exact org/user/issuer/subject under `FOR SHARE` inside
the non-owner `WithOrg` transaction and checks the current role. Role changes and
membership deletion must wait until commit or rollback. The preliminary role
does not grant operation authority. Unknown actions and missing proofs deny.

The transaction clears other auth lookup contexts before invoking the callback.
Its queries must still repeat explicit org/resource predicates. The callback owns
its mutation's atomic audit insert and may return a typed business error; storage
and authorization setup/commit failures remain generic. Publish callback results
only after the helper returns success, since commit can fail after the callback.

This helper implements ADR0016/0018's operation boundary. It adds no route, token
scope, state/secret/run permission or completed WP. Browser mutation Origin/CSRF,
request credential verification and approved handler contracts remain required.
