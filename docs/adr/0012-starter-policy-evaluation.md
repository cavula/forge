# ADR 0012: Starter plan policy evaluation

Status: Accepted. Approval: ARCHITECT role, 2026-10-23.
Owner: POLICY. Scope: WP-1.9 Rego library; no public API changes.

Evaluate native OpenTofu/Terraform `show -json` plan objects using Rego v1.
Accept format major version 1 and validate the consumed resource-change shape;
missing resource_changes means no resource changes. Malformed/unsupported input
denies with FORGE-PLAN-INVALID. The embedding caller must also deny evaluation
errors, undefined results and resource/time-limit failures.

Ten stable starter IDs cover seven AWS controls, destructive/IAM change approval
and tag warnings. They inspect changed managed resources, including replacements;
no-op, read and pure delete changes skip after-value security checks. Unknown or
missing security-critical fields deny their control; unrelated computed values
do not. CIDRs require valid syntax, matching address family and semantic network
comparison; malformed nested unknown masks deny the plan. Exact resource
types/fields and limitations are documented in policies.

The decision exposes only sorted rule IDs, never resource addresses, values or
credentials. Deny overrides other results. Approval findings require human
approval; passing policy never grants permission to apply. Warnings do not deny.
The run workflow still enforces identity, authorization and human approval.

These are conservative starter controls, not provider-wide compliance coverage.
The later Go SDK integration must bind a trusted saved plan to its decision and
test cancellation, resource limits and secret-safe errors. CI must run Rego tests
and coverage before WP-1.9 can be DONE. Rule IDs remain stable; rule changes need
review and tests. No remote policy bundles or evaluation-time network calls.

ARCHITECT independently verified strict compilation, 59 passing tests and 100%
Rego coverage. Regression checks deny equivalent expanded IPv6 world networks
and malformed critical unknown masks. This accepts the library slice only;
embedded evaluation and workflow integration remain required for WP completion.
