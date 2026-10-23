# M1 Temporal RunWorkflow

RunWorkflow uses pinned Temporal Go SDK v1.50.0 and ADR0019's typed activities.
This increment adds the manual-approval lifecycle with test activities only.
It registers no production worker/adapters and starts no infrastructure process.

Activity budgets and sanitized error types implement ADR0019. Policy denial or
malformed decisions stop before approval; a successful evaluator still grants no
apply authority. Retries preserve operation keys and require adapters to attach
to the original job. ExecuteApply's options permit one attempt only.

Signals wake trusted journal reads without supplying authority. Approval's24h
deadline bounds journal reads and admission; a27h safety timer and bounded5m
cleanup apply. Callers still need RejectDuplicate/28h caps and durable15m queue
checks. Canonical evidence is required for quiescence; denied admission cannot
become successful apply. Independent deadline/evidence regression tests pass.

Authentication, durable commands, immutable bindings, real Temporal history,
runner fencing/quiescence and LocalStack acceptance remain required.
