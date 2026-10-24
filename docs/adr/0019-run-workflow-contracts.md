# ADR 0019: M1 IaC RunWorkflow and immutable apply authorization

Status: Accepted by ARCHITECT role, 2026-10-23, with root cross-review before
consumer protobuf implementation, for the exact additive contracts/design below.
Owner: ARCHITECT; implementation: ORCHESTRATION; required reviewer: QA-SECURITY.
Scope: WP-1.5 and additive run contracts within M1. Dependencies: ADR0009/0011/
0016 authentication, ADR0018 stack revisions, WP-1.3 state, WP-1.6 runners,
WP-1.8 credentials, and ADR0012/0014 policy. Interfaces/mocks may be implemented
after explicit acceptance; production execution waits for those dependencies.
Neither the current worker/runner placeholders nor state schema implement them.

## Compatibility and exact proposed protobuf declarations

Keep package `forge.v1`, Go option
`github.com/cavula/forge/gen/go/forge/v1;forgev1`, every existing filename and all
existing Run fields 1–9, RunKind/RunStatus/Engine values unchanged. Add these new
files; import entities, binding and decision types where referenced. No existing
declaration moves, new Run fields, arbitrary status setter or raw artifact RPC.

```proto
// run_plan_binding.proto
message RunPlanBinding {
  string binding_sha256 = 1;
  string binary_plan_sha256 = 2;
  string plan_json_sha256 = 3;
  string policy_bundle_sha256 = 4;
  string policy_decision_sha256 = 5;
}
// run_policy_decision.proto
message RunPolicyDecision {
  bool allowed = 1;
  bool requires_approval = 2;
  repeated string deny_rule_ids = 3;
  repeated string warn_rule_ids = 4;
  repeated string approval_rule_ids = 5;
}
// run_details.proto
message RunDetails {
  Run run = 1;
  uint64 configuration_revision = 2;
  string configuration_sha256 = 3;
  RunPlanBinding plan = 4;
  RunPolicyDecision policy = 5;
  bool cancellation_requested = 6;
  string failure_code = 7;
}
// run_create.proto
message CreateRunRequest {
  string stack_id = 1;
  uint64 expected_configuration_revision = 2;
  string idempotency_key = 3;
}
message CreateRunResponse { RunDetails details = 1; }
// run_get.proto
message GetRunRequest { string id = 1; }
message GetRunResponse { RunDetails details = 1; }
// run_list.proto
message ListRunsRequest {
  string stack_id = 1;
  int32 page_size = 2;
  string page_token = 3;
}
message ListRunsResponse {
  repeated RunDetails runs = 1;
  string next_page_token = 2;
}
// run_approve.proto
message ApproveRunRequest {
  string id = 1;
  string binding_sha256 = 2;
  string idempotency_key = 3;
}
message ApproveRunResponse { RunDetails details = 1; }
// run_discard.proto
message DiscardRunRequest {
  string id = 1;
  string binding_sha256 = 2;
  string idempotency_key = 3;
}
message DiscardRunResponse { RunDetails details = 1; }
// run_cancel.proto
message CancelRunRequest { string id = 1; string idempotency_key = 2; }
message CancelRunResponse { RunDetails details = 1; }
// run_service.proto
service RunService {
  rpc CreateRun(CreateRunRequest) returns (CreateRunResponse);
  rpc GetRun(GetRunRequest) returns (GetRunResponse);
  rpc ListRuns(ListRunsRequest) returns (ListRunsResponse);
  rpc ApproveRun(ApproveRunRequest) returns (ApproveRunResponse);
  rpc DiscardRun(DiscardRunRequest) returns (DiscardRunResponse);
  rpc CancelRun(CancelRunRequest) returns (CancelRunResponse);
}
```

These RPCs expose metadata only. `plan`/`policy` are absent until their trusted
records exist; absent/zero/unknown values never grant authority. `Run.commit_sha`
is empty while unresolved, then set once to the fetched canonical lowercase Git
object ID (40 or 64 hex characters). RunKind is server-set IAC; M1 rejects Ansible,
drift and unknown engines/kinds before dispatch. Terraform is operator-supplied
only; OpenTofu is the default. No request supplies org, actor, role, approval flag,
configuration, plan bytes, credential, arbitrary commit/ref or executable options.

Require canonical nonzero UUID IDs/idempotency keys, revision 1..MaxInt64 and
lowercase 64-hex SHA-256 strings. Limit requests to 4 KiB. Get/List need an active
stack or retained historical same-org run; archived stacks cannot start work.
List uses UUID ascending keysets, default/maximum page size 20, and canonical
unpadded base64url `v1:<authorized-org>:<stack>:<last-run>`, maximum 192 bytes.
Validate every component and reject another org/stack; it is never authority.
Bound responses to 4 MiB. TypeScript revisions use bigint, never Number.
Use ADR0018's generic authentication/NotFound/error rules; busy/invalid phase is
FailedPrecondition, stale configuration/binding Aborted, reused idempotency key
with different validated arguments AlreadyExists. Failure codes are fixed safe
identifiers, not diagnostics: PREPARE_FAILED, PLAN_FAILED, POLICY_DENIED,
POLICY_FAILED, APPROVAL_TIMEOUT, AUTHORIZATION_CHANGED, STALE_BINDING,
PHASE_TIMEOUT, APPLY_FAILED, APPLY_OUTCOME_UNKNOWN, or INTERNAL.

## Explicit authority and transactional admission

Add explicit actions `run.enqueue`, `run.approve`, `run.cancel`, `run.discard`;
`resource.write` grants none of them. Reader gets metadata.read only; writer/admin
get enqueue/cancel/discard; only admin gets approve. Unspecified/unknown roles or
actions deny, including for admin. M1 approval requires a verified interactive
OIDC browser session and current admin membership: API tokens, runners, webhooks,
service accounts, policy and AI cannot approve. Every allowed plan still needs a
human approval in M1; automatic approval is deferred. Self-approval by an admin
is allowed in this bounded slice; separation of duties would require a later ADR.
Other token mutations remain unbound until explicit scope intersection passes.

For every operation re-read current membership under FOR SHARE, then stack, then
run in consistent lock order; use non-owner WithOrg and explicit org predicates.
Org comes only from verified membership, never request/header/workflow guesses.
Revalidate enqueue actor's current enqueue permission in Prepare and BeginApply;
revalidate the recorded human approver's current admin membership in BeginApply.
Removed/demoted membership or expired/revoked original credentials before an
accepted command deny that command; accepted approvals store human provenance,
not session credentials, and require current membership again at apply admission.
Cookie mutations retain exact Origin/CSRF checks. Admission, command journal,
idempotency result, outbox event and fixed-action audit commit atomically.

Create locks the active stack FOR SHARE, checks expected revision and absence of
active state lock, snapshots validated immutable configuration, and inserts the
QUEUED run. M1 permits one nonterminal run per stack via a database invariant;
unknown statuses count as active. This coordinates with ADR0018 Update/Delete's
FOR UPDATE guard. No network call occurs while this transaction holds locks.
Immutable snapshot/configuration digest and actor references are stored outside
Temporal history. The transactional outbox starts `forge/run/<org>/<run>` with
RejectDuplicate workflow-ID reuse; duplicate dispatch never creates a new run.
Public Create resolves the saved branch during Prepare; a future authenticated
VCS-event adapter must pin its verified event commit before planning, separately
reviewed under WP-1.4. Client-selected object IDs are not accepted by this API.

Approve/Discard require NEEDS_APPROVAL and exact trusted binding. Approve records
an immutable human decision; Discard atomically revokes any unapplied approval
and closes DISCARDED. Cancel records cancellation for any nonterminal phase and
prevents a later BeginApply. Terminal commands fail unless replaying the same
accepted idempotency key. Keys are unique by org/actor/action, retained with the
run, and always checked after current authorization; exact repeats return current
run metadata without repeating effects/audit. Duplicate or late wakeups are inert.

## Immutable artifact and apply binding

Prepare resolves the immutable configuration revision to a fetched detached
commit; persist that commit once. Runner checkout must independently enforce
repository egress/SSRF controls, symlink/path containment and protected environment
rules from ADR0018. Pin the engine/version/operator-approved binary digest and
provider lockfile digest. Secrets use frozen version references, never plaintext
in the snapshot metadata; credential issuance is separately reauthorized.
GeneratePlan saves a binary plan, then derives JSON with `show -json` from that
exact saved file using the same engine binary. Never run a fresh plan at apply.
Store artifacts encrypted, scoped to org/stack/run, immutable and content
addressed; trusted storage computes digests and authenticates bytes on retrieval.
Runner-supplied URLs, hashes and success claims alone establish no trusted record.
Trusted supervision seals the saved binary before deriving JSON and verifies job
provenance. Runners are untrusted execution principals: rootless/ephemeral jobs,
no host credentials or DB/Temporal access, and short-lived job/audience/fence-bound
capabilities. Only trusted control-plane activities may admit apply. Digests prove
identity of bytes, not safety of IaC/providers; runner isolation remains WP-1.6.

Persist the complete tuple: org/stack/run, configuration revision/digest, resolved
commit, engine/version/binary digest, provider lock digest, frozen secret-version
set digest, base state version/digest, binary-plan and exact JSON digests, reviewed
policy bundle digest, and policy decision digest. The absent initial state has an
explicit `none` marker. Pin policy source/capability version for this run; before
apply require the currently active reviewed policy bundle still matches, otherwise
fail STALE_BINDING and create a new run. No silent replan or policy replacement.
ADR0014 evaluates only the trusted JSON bytes/digest; errors/deny fail closed.
Record allowed/requires_approval plus sorted unique deny/warn/approval rule IDs.
EvaluatePolicy returns sanitized nonretryable POLICY_DENIED/POLICY_FAILED for
denied/malformed decisions. DecisionID alone grants nothing: BeginApply rereads
trusted rows. Rule IDs use internal/policy/evaluate.go's fixed validated allowlists,
making the LF-framed decision digest below unambiguous.

For deterministic digests use H(parts): SHA-256 over each UTF-8 part prefixed by
its unsigned 64-bit big-endian byte length. Configuration digest uses domain
`forge.configuration.v1`, then name, repository URL, branch, directory, engine
token, version, decimal environment count and sorted environment name/value pairs.
Frozen secret versions are bound separately below. Policy-decision digest
uses `forge.policy-decision.v1`, JSON digest, bundle digest, lowercase boolean
strings allowed/requires_approval, then each sorted rule list joined by LF.
Binding digest uses `forge.run-plan.v1`, org, stack, run, revision, configuration
digest, commit, engine, version, binary digest, provider-lock digest, secret-set
digest, base-state-version ID, base-state digest, binary-plan digest, JSON digest,
bundle digest, decision digest, each a separate part. Secret-set digest uses
`forge.secret-versions.v1`, decimal count, then sorted secret name/version-ID pairs.
UUIDs/digests/commit are canonical; numbers are base-10 without leading zeroes;
engine tokens are `opentofu`/`terraform`. Empty collections include count `0`.

BeginApply is the sole admission point: transactionally recheck active current
stack revision/digest, resolved commit and entire trusted tuple, current allowed
policy bundle/decision, current memberships, exact human approval, cancellation,
and unchanged base state. Reserve one durable (org,stack) apply gate/fence and
one immutable apply job ID. Integrate the HTTP state lock owner with that job;
the backend must accept state writes only for its current fence/lock owner.
No generic runner credential grants state/secret access. WP-1.3's separate state
permission/protocol ADR must implement this contract before real apply wiring.

The gate is not released/reassigned merely because a lease/Temporal timeout
expires. Start the apply process at most once per job: persist its launch claim
before launch; a crash in that gap fails closed. Repeated delivery only attaches
to the same job/result, never launches another apply. Gate/HTTP lock release
requires confirmed process quiescence and persisted state outcome; uncertain
launch/completion retains a quarantined gate/lock, fails APPLY_OUTCOME_UNKNOWN
and requires separately authorized operator reconciliation. Fences alone cannot
stop an old process's cloud side effects. Do not claim exactly-once cloud changes.

## Workflow interface, transitions and bounded failure behavior

Go-only interfaces below are approved for mocks after acceptance; no public
runner/job protocol is approved. Every activity receives trusted Ref{OrgID,RunID}
and an operation key `<run>/<activity>/<phase>`; payloads/results contain IDs, digests, phase,
safe codes and timestamps only. Configuration/env/plan/state/credentials remain
behind opaque stored references. Every activity validates its persisted run org.

```go
type RunStatus = forgev1.RunStatus
type RunInput struct { OrgID, RunID string } // trusted admission/outbox only
type RunResult struct { RunID string; Status RunStatus; FailureCode string }
type Ref struct { RunInput; OperationKey string }
type Record struct {
  StackID, SnapshotID, ArtifactSetID, DecisionID, ApprovalID, ApplyJobID string
  ConfigurationRevision uint64
  Status RunStatus
  BindingSHA256 string
  CancellationRequested bool
}
type TransitionInput struct { Ref; Expected, Next RunStatus }
type ApplyInput struct { Ref; BindingSHA256, ApprovalID string }
type JobInput struct { Ref; JobID string }
type Outcome struct { EvidenceID string; Succeeded, Quiescent bool }
type FinishInput struct { Ref; Status RunStatus; FailureCode, EvidenceID string }
type Activities interface {
  Load(context.Context, Ref) (Record, error)
  Transition(context.Context, TransitionInput) (Record, error)
  Prepare(context.Context, Ref) (Record, error)
  GeneratePlan(context.Context, Ref) (Record, error)
  EvaluatePolicy(context.Context, Ref) (Record, error)
  ReadCommand(context.Context, Ref) (Record, error)
  BeginApply(context.Context, ApplyInput) (Record, error)
  ExecuteApply(context.Context, JobInput) (Outcome, error)
  StopAndReconcile(context.Context, Ref) (Outcome, error)
  Finish(context.Context, FinishInput) (RunResult, error)
}
```

Ref/result structures use opaque reference UUIDs and the immutable metadata tuple
above, not serialized StackConfiguration. Transition/Finish use conditional row
updates plus unique operation keys and atomic audit; stale writes cannot resurrect
terminal runs. Temporal is deterministic: workflow time/timers/selectors only;
all I/O and wall-clock observations are activities. No whole-workflow retry,
reset-to-reapply, child execution or ContinueAsNew is enabled in M1.

The only normal path is QUEUED -> PREPARING -> PLANNING -> POLICY_CHECK ->
NEEDS_APPROVAL -> APPLYING -> FINISHED. Deny/evaluation failure, stale binding,
authorization loss, activity exhaustion or deadline produce FAILED. Explicit
Discard is only NEEDS_APPROVAL -> DISCARDED. Cancellation from any nonterminal
phase produces CANCELED after confirmed stop; no rollback is implied. If success
was durably recorded before cancellation admission, FINISHED wins. If apply
outcome cannot be proved, FAILED/APPLY_OUTCOME_UNKNOWN wins and lock remains.
started_at is set once entering PREPARING; finished_at once on terminal commit.

Commands are durable authorized database records; outbox sends `run-command`
with only a command UUID as a wakeup. Workflow reads the journal at phase
boundaries and on signals, never trusts a signal's approval/org/status payload.
ReadCommand always rereads current journal state; read keys do not cache a decision.
BeginApply serializes approval/discard/cancel races on the run and gate rows.
Cancel uses activity cancellation plus heartbeat-driven runner stop, with
WaitForCancellation=true; disconnected bounded cleanup persists safe outcomes.
Never mark CANCELED or release a lock merely because cancellation was requested.

| Operation | StartToClose / ScheduleToClose | Retry maximum |
| --- | --- | --- |
| Load, transition, command, BeginApply, Finish | 10s / 2m | 3 |
| Prepare | 5m / 10m; heartbeat 10s | 3, attach same job |
| GeneratePlan | 20m / 30m; heartbeat 10s | 3, attach same job |
| EvaluatePolicy | 5s / 30s; evaluator limit 1s | 3 |
| ExecuteApply | 60m / 60m; heartbeat 10s | 1 |
| StopAndReconcile | 2m / 5m; heartbeat 10s | 3 |

Queue deadline is 15m, approval wait 24h, workflow execution/run caps 28h.
Workflow-owned timers enforce phase deadlines and reserve cleanup before the
outer cap; a separate reconciler quarantines gates after hard timeout/termination.
Backoff is 1s, coefficient 2, maximum 10s. Retry only sanitized transient transport/
storage failures; invalid input/auth/policy/process exit/stale/conflict failures
are nonretryable. Prepare/plan retries attach to a stable job, not another process;
successful artifacts/results are immutable. Apply transport uncertainty triggers
reconciliation, never a retry launch. Stop/cleanup does not force-unlock a live
job. Runners independently enforce job deadlines if a worker loses contact.
All adapter/Temporal errors use safe codes without raw SDK/tool output.

## Review slicing, evidence and recorded choices

Acceptance here authorizes only the exact declarations/design. First publish each
small standalone binding/decision message, one approved field per slice if needed;
then details, then each RPC message file (request and response may land separately
in the stable filename). Introduce RunService with GetRun, then one RPC at a time.
Every PR stays strictly below 500 changed lines including Go/Connect/TS generation,
tests/docs; regenerate all clients and run buf lint/build/real-base breaking and
wire/descriptor checks in every contract slice. Do not move the M0 baseline.

Temporal testsuite must prove exact transitions, denied/malformed policy, human
wait, approval timeout, cancel at every phase, cancel/apply/discard races, repeated
signals, outbox replay, activity retries/exhaustion, deterministic replay, fixed
deadlines, unchanged binding, and no second apply after lost acknowledgment.
Fakes must assert no apply after stale revision/commit/artifact/policy/state or
demoted/deleted approver/requestor; rejected org/signals cannot become authority.
Real PostgreSQL non-owner/FORCE-RLS tests must cover both tenant directions,
missing/reset context, membership/stack/admission races, duplicate job/fence
claims, lock quarantine and audit rollback. QA-SECURITY reviews workflow, runner,
state, artifact/secret leak and credential boundaries before any real exposure.
Mock CI establishes orchestration behavior only. WP-1.5/WP-1.9 remain incomplete
until hosted CI AC passes; the M1 gate additionally needs the real LocalStack
push -> policy -> human approve -> apply -> versioned state -> audit flow with
the real runner/backend. Stop at that M1 gate; Ansible execution remains M2.

Record in OPEN_QUESTIONS/STATUS: admin-only interactive approval, permitted admin
self-approval, mandatory human approval, one active run per stack, concrete timeout
defaults and policy-change invalidation are reversible M1 choices. State protocol,
VCS trusted enqueue adapter, operator reconciliation, artifact storage/key loading,
job credential/fence enforcement and runner provenance remain dependent gates;
this ADR does not claim they exist or authorize an unreviewed fallback.

References: [Temporal activity timeouts/retries](https://docs.temporal.io/develop/go/activities#timeouts),
[Temporal Go activity cancellation](https://github.com/temporalio/sdk-go/blob/main/internal/activity.go),
[Temporal workflow identity](https://github.com/temporalio/sdk-go/blob/main/internal/workflow.go).
