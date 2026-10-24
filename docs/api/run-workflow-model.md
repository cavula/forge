# M1 RunWorkflow model

ADR0019 approves the metadata types and activity interface in
`internal/runs/model.go`. This slice supplies structural validation only; it
registers no Temporal workflow, RPC, worker, runner, state or credential path.

`RunInput.Validate` accepts canonical lowercase nonzero UUID references. A valid
reference carries no identity or tenant authority. Admission must supply the org
from authenticated membership; activities must independently verify stored org,
current membership and their own authorization preconditions.

`NewRef` deterministically creates `<run>/<ActivityMethod>/<RUN_STATUS_NAME>` for
an approved activity and existing IaC phase. Retry attempts reuse that key. Reads
still load current records; keys never turn a prior read into an approval cache.

`ValidateTransition` checks only the IaC graph, including failure/cancellation and
discard from NEEDS_APPROVAL. A valid edge into APPLYING grants no permission.
Adapters must revalidate immutable artifacts, policy, human approval, current
configuration/roles/state and the exclusive gate before applying. DecisionID is
an opaque locator. EvaluatePolicy must fail denied/malformed decisions with safe
nonretryable POLICY_DENIED/POLICY_FAILED in the later Temporal adapter.

Results accept only fixed safe failure identifiers; FAILED requires a code and
other terminal results forbid one. Validators never echo input in diagnostics.
The model contains IDs, digests, enums, counters and booleans; configuration,
environment, artifact/state bytes and credentials stay behind stored references.
Tests cover the graph, malformed references, stable operation keys and this
metadata boundary. Runtime authorization and real I/O acceptance remain open.

Local validation: `go test -race ./internal/runs` passes with 97.6% statement
coverage; `go vet ./internal/runs` passes. Hosted CI acceptance remains pending.
