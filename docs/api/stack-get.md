# Stack lookup message contracts

ADR0018 approves `forge.v1.GetStackRequest` with only string `id` at field 1 and
`GetStackResponse` with the existing `Stack` message at field 1. Both declarations
live in the stable `forge/v1/stack_get.proto` file. This slice adds no service,
RPC or handler; prior generated contracts remain byte-identical.

The future authenticated read requires `metadata.read`. Organization authority
comes from verified identity and current membership, never from request fields.
The request carries no organization or role. Its ID must later be validated as a
canonical lowercase nonzero UUID. Absent, foreign and archived stacks must return
the same NotFound after authorization within the caller's organization.

The response retains server-assigned Stack identity, organization, timestamp and
configuration revision. TypeScript represents the uint64 revision with `bigint`
and JSON with a decimal string. Environment values are non-secret and visible to
organization readers; they must never enter logs, audit payloads or AI requests.

Buf compatibility and deterministic generation plus Go/TypeScript protobuf, JSON
and descriptor checks validate this additive contract. They do not establish
authenticated storage isolation or complete WP-1.2's hosted CI acceptance.
