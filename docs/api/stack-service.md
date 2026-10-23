# Stack service lookup contract

ADR0018 introduces `forge.v1.StackService` incrementally. This slice declares only
the unary `GetStack(GetStackRequest) returns (GetStackResponse)` method, importing
the existing messages from `forge/v1/stack_get.proto`. Its Connect procedure is
`/forge.v1.StackService/GetStack`; its generated mount prefix is
`/forge.v1.StackService/`. Create, List, Update and Delete remain later slices.

The generated default handler returns Unimplemented. The application does not
mount this service or provide an authentication/storage handler in this slice.
Before exposure, GetStack requires verified identity, current membership and
`metadata.read`; it must derive organization authority from authorization and use
a non-owner WithOrg transaction with explicit organization predicates. Request
IDs never establish authority. Absent, foreign and archived rows must share the
same NotFound behavior within an authorized organization.

Tests verify the exact unary descriptor, procedure, existing message wire
formats, lossless revision JSON, generated Unimplemented transport behavior and
absence of undeclared routes. Pinned deterministic generation and Buf breaking
checks cover both the exact GetStack parent and fetched main. These contract
checks do not complete authenticated CRUD, hosted CI acceptance or WP-1.2.
