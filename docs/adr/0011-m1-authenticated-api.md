# ADR 0011: Authenticated M1 API and tenant resolution

Status: Accepted by ARCHITECT, 2026-10-22; QA-SECURITY review gates auth wiring.
Owners: CORE-BACKEND and ARCHITECT. Scope: WP-1.1 and WP-1.2, within M1.

## Authentication and tenant boundary

Use github.com/coreos/go-oidc/v3 and golang.org/x/oauth2 with pinned, scanned
versions. Configure the issuer, client and exact callback URL through operator
configuration, never a request URL. Use authorization code flow with S256 PKCE,
one-use short-lived state bound to the initiating browser and a checked nonce.
Verify signatures through issuer discovery/JWKS, issuer, audience and expiry;
never enable verifier bypass options. Apply bounded outbound timeouts. Production
requires HTTPS; explicit loopback HTTP is allowed only in development.
Keep flow records server-side, consume atomically, and prevent callback replay.
Use opaque random expiring browser sessions with only one-way verifiers stored,
HttpOnly/Secure/SameSite cookies and explicit Origin/CSRF checks for mutations.
Neither provider tokens nor session credentials belong in protobuf or logs.

Keep users tenant-local. A verified issuer/subject may select an organization
with `X-Forge-Org-ID`, but the header is never authorization. A dedicated short,
read-only membership-resolution transaction sets verified issuer/subject context
and reads only the matching user using explicit issuer, subject and org predicates.
A separate SELECT-only users RLS policy permits only those verified-principal
rows; existing forced tenant RLS and write policies remain. Do not set forge.org_id
from the header. Clear resolution context when its transaction ends; pass only
successfully resolved membership to WithOrg. Re-read current role/membership for
each operation; deletion or demotion must take effect without session renewal.
Missing identity/membership fails closed without disclosing another tenant.

API-token verification uses a separate narrow read-only lookup transaction keyed
by the canonical public selector. Its forced-RLS SELECT policy reveals only that
credential's verifier/binding metadata to trusted authentication code, no tenant
resources. This lookup is not authorization. Verify the full token digest, expiry
and revocation before adopting its stored org/user binding; then check current
membership and intersect scopes with role permissions inside the operation's
WithOrg transaction. A header cannot override token ownership. Keep ordinary
tenant CRUD and token issuance/revocation under explicit org predicates and RLS.
Resolve absent selectors with generic errors; bound authentication attempts.
QA must test lookup-context reset, cross-tenant hints, revocation and demotion.

Provide an explicit operator bootstrap command with separately supplied owner
credentials to atomically create the initial org, known issuer/subject admin
and audit entry. Never make bootstrap a public endpoint or silently rerun it at
server startup. Repeated/conflicting bootstrap fails safely. Subsequent org/team
and membership operations require admin permission plus transactional audit;
prevent removing/demoting the last admin. Team grouping grants no extra authority.

## Approved first protobuf contract

ARCHITECT explicitly approves these additive declarations in package forge.v1,
with the existing Go package option and existing User entity unchanged:
`GetCurrentUserRequest {}`; `GetCurrentUserResponse { User user = 1; }`;
`IdentityService.GetCurrentUser(GetCurrentUserRequest) returns (GetCurrentUserResponse)`.
Use new identity_get_current_user.proto for messages and identity_service.proto
for the service, importing the existing entities.proto. No request org/role fields
are allowed. Return only the current resolved membership under metadata.read;
missing credentials return Unauthenticated, unauthorized org selection returns
PermissionDenied. Bind no handler until authentication/resolution gates pass.

Later org/team/token and stack RPC names/fields require a concrete approved ADR
before proto edits. Stack CRUD will require metadata.read/resource.write, server
assigned org/IDs, validated repo/branch/path/engine/version and separate typed
non-secret environment variables; secrets use the dedicated secret interface.
Mutations and audit entries commit together; client input never supplies a role
or tenant authority. No arbitrary SQL filters or unrestricted field masks.

## Review slices and acceptance

Land credential persistence/resolution, OIDC verification, browser flow/session,
bootstrap, and RPC handlers as separately tested slices. Generate and measure
request/response contracts first, service second if needed, then authenticated
handler. Each PR must remain below 500 changed lines including generated clients,
tests and docs; one RPC is an upper bound, not a size exemption. Keep filenames
stable, regenerate Go/Connect/TS and run real-base buf breaking in each proto PR.
No prototype endpoint or insecure stub may substitute for the complete flow.
Then approve and implement individual org/team/token/stack RPCs sequentially.

WP-1.1 requires provider-backed login, negative/replay tests, isolated org/team
operations, scoped expiring/revocable tokens and current-membership enforcement.
WP-1.2 requires authorized CRUD with cross-tenant tests; M1 remains gated on the
full LocalStack MVP flow. Tests include I/O integration, leak checks and >=70%
business coverage; mandatory QA-SECURITY review and green CI precede acceptance.
Provider deployment/client registration and bootstrap issuer/subject are operator
configuration choices; no real credentials are needed for deterministic CI IdP
fixtures. UI uses these approved APIs and cannot bypass backend authorization.

Sources: [go-oidc](https://github.com/coreos/go-oidc) and
[oauth2 PKCE API](https://pkg.go.dev/golang.org/x/oauth2).
