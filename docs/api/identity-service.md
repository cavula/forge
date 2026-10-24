# Identity service contract

ADR0011 approves `forge.v1.IdentityService.GetCurrentUser`, a unary RPC taking
the empty `GetCurrentUserRequest` and returning `GetCurrentUserResponse.user`.
The existing `User` entity represents one organization-local membership.
The request cannot assert an organization, role, or permission.

This slice generates the Go, Connect and TypeScript service clients and
descriptors. It binds no server handler. Authentication and membership-resolution
security gates must pass before the RPC is served; an unauthenticated prototype
handler is not an implementation substitute.

When implemented, the RPC requires `metadata.read` on the resolved membership.
Missing credentials return `Unauthenticated`; unauthorized organization selection
returns `PermissionDenied`. Organization hints do not authorize tenant access,
and the current role must be read for each operation.

Validation: pinned Buf generation; lint, format, build and breaking against the
actual PR base; generated Go compilation and TypeScript checking; wire roundtrip
and service-descriptor tests. These checks verify the contract and do not claim
that login, API authentication or WP-1.1 is complete.
