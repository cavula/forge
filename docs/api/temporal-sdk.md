# Temporal SDK foundation

WP-1.5 uses pinned `go.temporal.io/sdk v1.50.0` under accepted ADR0019.
The SDK and its test suite dependency are pinned separately from OPA so each
review slice stays below 500 changed lines. Go remains at the existing 1.26
module requirement. No worker or workflow is registered by this foundation.

Typed activity references contain metadata only; structural validation never
authorizes an organization, approval or apply. Trusted storage, authorization,
job fences and runner adapters remain separate implementation gates.

Model race tests and vet pass; the consuming workflow uses the same frozen
dependency graph in isolated Temporal test-suite simulations. Hosted CI,
real Temporal I/O and the complete LocalStack workflow remain required.
