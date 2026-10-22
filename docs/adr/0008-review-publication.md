# ADR 0008: Publish M0 as independently checked review slices

Status: Accepted by ARCHITECT, 2026-10-21.
Owner: PLATFORM with ARCHITECT review. Milestone: M0 only.

## Decision

Publish a linear stack of PRs based on the preceding review branch, beginning
with PR #1. Each diff remains below 500 added plus deleted lines. The user
explicitly approved a one-time exception for web/pnpm-lock.yaml; every other
file, including generated clients, still counts toward the limit. The exception
does not waive tests, documentation, architecture review or security checks.

Introduce Go, PostgreSQL and contract checks with the first corresponding code.
Each intermediate branch runs tests for all components present on that branch.
The final branch replaces the progressive review workflow with the complete
unconditional M0 workflow, including clean-clone Compose startup and image scans.
Every PR must have passing checks at its own head before it is ready for review.

The original roadmap remains authoritative: Valkey is optional and no M1
operations are introduced. ADR0007 authorizes the per-entity contract file split;
this publication ADR does not authorize wire-level API changes.

## Consequences

Review and merge PRs in order. After a parent merges, retarget its child to main
and confirm the displayed diff and checks before merging. Do not merge the old
combined validation branch, which exists only as acceptance evidence. The final
review branch contains the complete runnable foundation. M1 remains gated on
M0 review/merge and the user's milestone decision.
