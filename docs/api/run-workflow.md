# M1 Temporal RunWorkflow

RunWorkflow uses [Temporal Go SDK v1.50.0](https://github.com/temporalio/sdk-go/tree/v1.50.0) from the official Go module proxy and
the accepted ADR0019 activity interface. It remains unbound: no production
worker or adapters are registered. Tests supply all activities.

Activity budgets and sanitized error types implement ADR0019. Policy denial or
malformed decisions stop before approval; a successful evaluator still grants no
apply authority. Retries preserve operation keys and require adapters to attach
to the original job. ExecuteApply's options permit one attempt only.

Signals only wake a trusted command reread; their bodies cannot grant approval.
The workflow preserves the prepared binding when a command refers to another
plan, and BeginApply must reject it against trusted rows. Uncertain apply delivery
never relaunches: bounded reconciliation supplies quiescence evidence, or Finish
records APPLY_OUTCOME_UNKNOWN with the durable gate retained by the adapter.

The workflow owns a 27h safety timer and 24h approval timer, and reserves at most
5m cleanup (StopAndReconcile capped at 3m, preserving 2m for Finish). Callers must
set RejectDuplicate workflow reuse and 28h execution/run
caps. Load must enforce the 15m queue deadline from durable admission time; the
metadata-only model deliberately does not carry wall-clock creation timestamps.

Validation uses an isolated origin/main module plus the frozen model. Tests
repeat the normal activity trace, reject forged signal approval, preserve a stale
binding and prove one ExecuteApply call after lost acknowledgment. This does not
replace server-history replay or real Temporal/runner/state integration tests.
Authentication, durable commands, artifact/state checks, runner deadlines,
fencing, reconciliation, QA review and hosted CI remain production gates.

The final isolated Temporal testsuite passes cancellation at every phase,
durable cancel/discard, policy denial/failure, approval/safety/phase/cleanup
deadlines, retry exhaustion and unsafe quiescence. Normal success and confirmed
quiescence are test-adapter evidence; no real infrastructure was applied.

Independent review found and reproduced an approval deadline race during a slow
command read. The workflow now races that read and BeginApply against its own
approval deadline and rechecks workflow time before accepting a result. Nonempty
reference IDs must be canonical UUIDs, and quiescence requires a canonical
evidence reference; malformed success cannot finish the run successfully.
