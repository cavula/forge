# M1 Temporal RunWorkflow

The preparation helper uses Temporal Go SDK v1.50.0, obtained from the official
Go module proxy. This first unbound increment advances QUEUED through
NEEDS_APPROVAL using the accepted ADR0019 activity interface. It registers no
production worker or activities, starts no runner and never applies.

Activity budgets and sanitized error types implement ADR0019. Policy denial or
malformed decisions stop before approval; a successful evaluator still grants no
apply authority. Retries preserve operation keys and require adapters to attach
to the original job. ExecuteApply's options permit one attempt only.

Dependencies are validated in an isolated origin/main module plus the frozen
run model. Authentication, durable commands, immutable artifact/state/approval
checks, runner deadlines, admission fencing, reconciliation and hosted CI remain
required before production exposure. The next source increment adds the full
manual-approval/cancellation lifecycle against test activities only.
