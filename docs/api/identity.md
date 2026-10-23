# Current-user contract

ADR0011 approves GetCurrentUserRequest (no fields) and GetCurrentUserResponse,
which contains the existing organization-local User. Callers cannot assert an
organization or role through the request. A later authenticated handler must
resolve current membership and enforce metadata.read before returning it.

Go and TypeScript clients are generated with the pinned Buf plugins. Wire tests
cover membership preservation and the request's empty field set. This message
slice registers no service or handler and does not expose login.
