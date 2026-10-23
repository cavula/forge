# ADR 0014: Embedded starter-policy evaluation

Status: Accepted by ARCHITECT role, 2026-10-23, for the bounded SDK slice below.
Owner: POLICY. Scope: WP-1.9 SDK slice; workflow integration remains required.

Compile the embedded, reviewed starter Rego with OPA Go SDK v1.21.3 at startup.
Use its Rego v1 query `data.forge.plan.decision`; retain the same CLI version.
The SDK's Go 1.26 floor matches the existing module. No public contracts change.
Only allow builtins required by the starter policy; deny network capabilities,
runtime policy loading, external bundles, printing and extension hooks.

Accept at most 1 MiB of native saved-plan JSON and nesting depth 64. Bind the
decision to SHA-256 of the exact copied bytes, checked against a digest from
trusted artifact storage. Reject duplicate keys, malformed/trailing JSON, hash
mismatch and unsupported input. Preserve exact numeric digits, capped at 256
characters, exponent -308 through 308 and finite float64 range before SDK
arbitrary-precision conversion.
Bound compilation and evaluation to one second or the caller's earlier deadline.
Oversized/failed/timed-out/undefined evaluation returns a denied zero decision
and one generic error; SDK diagnostics and plan values are never returned/logged.

Validate output shape, booleans, sorted unique known rule IDs and allowed/approval
invariants. Passing policy does not authorize apply; trusted workflow identity,
saved binary-plan binding and human approval remain required integration gates.
These conservative limits are reversible configuration choices for a later slice.
WP-1.9 stays in progress until its workflow and full M1 end-to-end gate pass CI.
