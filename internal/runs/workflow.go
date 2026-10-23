package runs

import (
	"errors"
	"time"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// These budgets implement ADR0019. Job retries attach to the original job;
// ExecuteApply never retries a launch after an uncertain acknowledgment.
func runActivityOptions(name string) workflow.ActivityOptions {
	opts := workflow.ActivityOptions{StartToCloseTimeout: 10 * time.Second,
		ScheduleToCloseTimeout: 2 * time.Minute, WaitForCancellation: true,
		RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2,
			MaximumInterval: 10 * time.Second, MaximumAttempts: 3,
			NonRetryableErrorTypes: []string{"PREPARE_FAILED", "PLAN_FAILED", "POLICY_DENIED", "POLICY_FAILED",
				"APPROVAL_TIMEOUT", "AUTHORIZATION_CHANGED", "STALE_BINDING", "PHASE_TIMEOUT",
				"APPLY_FAILED", "APPLY_OUTCOME_UNKNOWN", "INTERNAL"}}}
	switch name {
	case "Prepare":
		opts.StartToCloseTimeout, opts.ScheduleToCloseTimeout = 5*time.Minute, 10*time.Minute
		opts.HeartbeatTimeout = 10 * time.Second
	case "GeneratePlan":
		opts.StartToCloseTimeout, opts.ScheduleToCloseTimeout = 20*time.Minute, 30*time.Minute
		opts.HeartbeatTimeout = 10 * time.Second
	case "EvaluatePolicy":
		opts.StartToCloseTimeout, opts.ScheduleToCloseTimeout = 5*time.Second, 30*time.Second
	case "ExecuteApply":
		opts.StartToCloseTimeout, opts.ScheduleToCloseTimeout = time.Hour, time.Hour
		opts.HeartbeatTimeout, opts.RetryPolicy.MaximumAttempts = 10*time.Second, 1
	case "StopAndReconcile":
		opts.StartToCloseTimeout, opts.ScheduleToCloseTimeout = 2*time.Minute, 5*time.Minute
		opts.HeartbeatTimeout = 10 * time.Second
	}
	return opts
}

func safeRunError(code string) error {
	if code == "" || ValidateFailureCode(code) != nil {
		code = "INTERNAL"
	}
	return temporal.NewNonRetryableApplicationError(code, code, nil)
}

func runFailureCode(err error, fallback string) string {
	var application *temporal.ApplicationError
	if errors.As(err, &application) && application.Type() != "" && ValidateFailureCode(application.Type()) == nil {
		return application.Type()
	}
	if temporal.IsTimeoutError(err) {
		return "PHASE_TIMEOUT"
	}
	return fallback
}

type runExecution struct {
	input          RunInput
	record         Record
	signals        workflow.ReceiveChannel
	deadline       workflow.Future
	approvalTimer  workflow.Future
	approvalExpiry time.Time
	discarded      bool
	applyAttempted bool
	applyScheduled bool
}

func (run *runExecution) ref(name string) Ref {
	ref, _ := NewRef(run.input, name, run.record.Status)
	return ref
}

func (run *runExecution) callRecord(ctx workflow.Context, name string, argument any) error {
	var record Record
	if err := run.call(ctx, name, argument, &record); err != nil {
		return err
	}
	for _, id := range []string{record.StackID, record.SnapshotID, record.ArtifactSetID, record.ApprovalID, record.ApplyJobID} {
		if id != "" && !canonicalUUID(id) {
			return safeRunError("INTERNAL")
		}
	}
	if !iacStatus(record.Status) || record.ConfigurationRevision > 9223372036854775807 {
		return safeRunError("INTERNAL")
	}
	if record.DecisionID != "" && !canonicalUUID(record.DecisionID) || record.BindingSHA256 != "" && !canonicalBinding(record.BindingSHA256) {
		return safeRunError("POLICY_FAILED")
	}
	run.record = record
	return nil
}

func (run *runExecution) readCommand(ctx workflow.Context) error {
	if run.signals == nil {
		return nil
	}
	var command Record
	if err := run.call(ctx, "ReadCommand", run.ref("ReadCommand"), &command); err != nil {
		return err
	}
	if command.ApprovalID != "" && !canonicalUUID(command.ApprovalID) {
		return safeRunError("INTERNAL")
	}
	run.record.ApprovalID = command.ApprovalID
	run.record.CancellationRequested = run.record.CancellationRequested || command.CancellationRequested
	run.discarded = run.discarded || command.Status == forgev1.RunStatus_RUN_STATUS_DISCARDED
	if run.record.CancellationRequested || run.discarded {
		return temporal.NewCanceledError()
	}
	return nil
}

func (run *runExecution) call(ctx workflow.Context, name string, argument, result any) error {
	if run.approvalExpired(ctx) {
		return safeRunError("APPROVAL_TIMEOUT")
	}
	if run.deadline != nil && run.deadline.IsReady() {
		return safeRunError("PHASE_TIMEOUT")
	}
	options := runActivityOptions(name)
	activityCtx, cancel := workflow.WithCancel(workflow.WithActivityOptions(ctx, options))
	defer cancel()
	future := workflow.ExecuteActivity(activityCtx, name, argument)
	if name == "ExecuteApply" {
		run.applyScheduled = true // Scheduling is not proof of process launch.
	}
	if run.signals == nil {
		return future.Get(ctx, result)
	}
	phaseDeadline := workflow.NewTimer(activityCtx, options.ScheduleToCloseTimeout)
	for {
		ready, wake, expired := false, false, false
		selector := workflow.NewSelector(ctx)
		selector.AddFuture(future, func(workflow.Future) { ready = true })
		selector.AddFuture(run.deadline, func(workflow.Future) { expired = true })
		selector.AddFuture(phaseDeadline, func(workflow.Future) { expired = true })
		if run.approvalTimer != nil {
			selector.AddFuture(run.approvalTimer, func(workflow.Future) {})
		}
		if name != "ReadCommand" {
			selector.AddReceive(run.signals, func(channel workflow.ReceiveChannel, _ bool) {
				channel.Receive(ctx, nil) // Wakeup only; never decode approval/org/status.
				wake = true
			})
		}
		selector.AddReceive(ctx.Done(), func(workflow.ReceiveChannel, bool) {})
		selector.Select(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if run.approvalExpired(ctx) {
			return safeRunError("APPROVAL_TIMEOUT")
		}
		if expired {
			return safeRunError("PHASE_TIMEOUT")
		}
		if wake {
			if err := run.readCommand(ctx); err != nil {
				return err
			}
		}
		if ready {
			return future.Get(ctx, result)
		}
	}
}

// prepare advances only through NEEDS_APPROVAL. Success is never authority to
// apply; BeginApply must recheck trusted policy, human approval and all bindings.
func (run *runExecution) prepare(ctx workflow.Context) error {
	if err := run.input.Validate(); err != nil {
		return safeRunError("INTERNAL")
	}
	run.record.Status = forgev1.RunStatus_RUN_STATUS_QUEUED
	if err := run.callRecord(ctx, "Load", run.ref("Load")); err != nil {
		return err
	}
	if run.record.Status != forgev1.RunStatus_RUN_STATUS_QUEUED {
		return safeRunError("INTERNAL")
	}
	steps := []struct {
		status   RunStatus
		activity string
	}{
		{forgev1.RunStatus_RUN_STATUS_PREPARING, "Prepare"},
		{forgev1.RunStatus_RUN_STATUS_PLANNING, "GeneratePlan"},
		{forgev1.RunStatus_RUN_STATUS_POLICY_CHECK, "EvaluatePolicy"},
		{forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL, ""},
	}
	for _, step := range steps {
		if err := run.readCommand(ctx); err != nil {
			return err
		}
		transition := TransitionInput{Ref: run.ref("Transition"), Expected: run.record.Status, Next: step.status}
		if err := ValidateTransition(transition.Expected, transition.Next); err != nil {
			return safeRunError("INTERNAL")
		}
		if err := run.callRecord(ctx, "Transition", transition); err != nil {
			return err
		}
		if run.record.Status != step.status {
			return safeRunError("INTERNAL")
		}
		if step.activity != "" {
			if err := run.callRecord(ctx, step.activity, run.ref(step.activity)); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunWorkflow is unbound: callers must configure RejectDuplicate and 28h run /
// execution limits; trusted activities provide authorization and durable fencing.
func RunWorkflow(ctx workflow.Context, input RunInput) (RunResult, error) {
	if input.Validate() != nil {
		return RunResult{}, safeRunError("INTERNAL")
	}
	run := runExecution{input: input, signals: workflow.GetSignalChannel(ctx, "run-command"),
		deadline: workflow.NewTimer(ctx, 27*time.Hour)}
	err := run.prepare(ctx)
	if err == nil {
		err = run.awaitApproval(ctx)
	}
	var outcome Outcome
	if err == nil {
		run.applyAttempted = true
		binding := run.record.BindingSHA256
		err = run.callRecord(ctx, "BeginApply", ApplyInput{Ref: run.ref("BeginApply"),
			BindingSHA256: binding, ApprovalID: run.record.ApprovalID})
		if err == nil && (run.record.Status != forgev1.RunStatus_RUN_STATUS_APPLYING || !canonicalUUID(run.record.ApplyJobID)) {
			err = safeRunError("INTERNAL")
		}
		if err == nil && run.record.BindingSHA256 != binding {
			err = safeRunError("STALE_BINDING")
		}
		if err == nil {
			run.approvalTimer, run.approvalExpiry = nil, time.Time{}
			err = run.call(ctx, "ExecuteApply", JobInput{Ref: run.ref("ExecuteApply"), JobID: run.record.ApplyJobID}, &outcome)
		}
	}
	return run.finish(ctx, err, outcome)
}

func (run *runExecution) awaitApproval(ctx workflow.Context) error {
	if !canonicalUUID(run.record.DecisionID) || !canonicalBinding(run.record.BindingSHA256) {
		return safeRunError("POLICY_FAILED")
	}
	run.approvalExpiry = workflow.Now(ctx).Add(24 * time.Hour)
	run.approvalTimer = workflow.NewTimer(ctx, 24*time.Hour)
	for {
		if err := run.readCommand(ctx); err != nil {
			return err
		}
		if run.record.ApprovalID != "" {
			return nil // BeginApply rechecks the human and immutable binding.
		}
		expired := false
		selector := workflow.NewSelector(ctx)
		selector.AddFuture(run.approvalTimer, func(workflow.Future) { expired = true })
		selector.AddFuture(run.deadline, func(workflow.Future) { expired = true })
		selector.AddReceive(run.signals, func(channel workflow.ReceiveChannel, _ bool) { channel.Receive(ctx, nil) })
		selector.AddReceive(ctx.Done(), func(workflow.ReceiveChannel, bool) {})
		selector.Select(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if expired {
			return safeRunError("APPROVAL_TIMEOUT")
		}
	}
}

func (run *runExecution) finish(ctx workflow.Context, cause error, outcome Outcome) (RunResult, error) {
	cleanup, cancel := workflow.NewDisconnectedContext(ctx)
	defer cancel()
	deadline := workflow.Now(cleanup).Add(5 * time.Minute)
	if outcome.Quiescent && !canonicalUUID(outcome.EvidenceID) {
		outcome = Outcome{}
		cause = safeRunError("INTERNAL")
	}
	if !outcome.Quiescent {
		stopOptions := runActivityOptions("StopAndReconcile")
		stopOptions.ScheduleToCloseTimeout = 3 * time.Minute // Reserve 2m for Finish.
		if cleanupActivity(cleanup, "StopAndReconcile", run.ref("StopAndReconcile"), &outcome, stopOptions) != nil {
			outcome = Outcome{}
		}
	}
	if outcome.EvidenceID != "" && !canonicalUUID(outcome.EvidenceID) || outcome.Quiescent && !canonicalUUID(outcome.EvidenceID) {
		outcome = Outcome{}
		cause = safeRunError("INTERNAL")
	}
	fallback := "INTERNAL"
	switch run.record.Status {
	case forgev1.RunStatus_RUN_STATUS_PREPARING:
		fallback = "PREPARE_FAILED"
	case forgev1.RunStatus_RUN_STATUS_PLANNING:
		fallback = "PLAN_FAILED"
	case forgev1.RunStatus_RUN_STATUS_POLICY_CHECK:
		fallback = "POLICY_FAILED"
	case forgev1.RunStatus_RUN_STATUS_APPLYING:
		fallback = "APPLY_FAILED"
	}
	status, code := forgev1.RunStatus_RUN_STATUS_FAILED, runFailureCode(cause, fallback)
	switch {
	case !outcome.Quiescent:
		code = "PHASE_TIMEOUT"
		if run.applyAttempted {
			code = "APPLY_OUTCOME_UNKNOWN"
		}
	case outcome.Succeeded && run.applyScheduled:
		status, code = forgev1.RunStatus_RUN_STATUS_FINISHED, ""
	case run.discarded:
		status, code = forgev1.RunStatus_RUN_STATUS_DISCARDED, ""
	case run.record.CancellationRequested || temporal.IsCanceledError(cause):
		status, code = forgev1.RunStatus_RUN_STATUS_CANCELED, ""
	case cause == nil:
		code = "APPLY_FAILED"
	}
	options := runActivityOptions("Finish")
	if remaining := deadline.Sub(workflow.Now(cleanup)); remaining <= 0 {
		return RunResult{}, safeRunError("INTERNAL") // Reconciler must retain/quarantine the gate.
	} else if remaining < options.ScheduleToCloseTimeout {
		options.ScheduleToCloseTimeout = remaining
		if options.StartToCloseTimeout > remaining {
			options.StartToCloseTimeout = remaining
		}
	}
	var result RunResult
	input := FinishInput{Ref: run.ref("Finish"), Status: status, FailureCode: code, EvidenceID: outcome.EvidenceID}
	if err := cleanupActivity(cleanup, "Finish", input, &result, options); err != nil {
		return RunResult{}, safeRunError("INTERNAL")
	}
	if result.RunID != run.input.RunID || result.Validate() != nil || result.Status != status || result.FailureCode != code {
		return RunResult{}, safeRunError("INTERNAL")
	}
	return result, nil
}

func (run *runExecution) approvalExpired(ctx workflow.Context) bool {
	return !run.approvalExpiry.IsZero() && !workflow.Now(ctx).Before(run.approvalExpiry)
}

func cleanupActivity(ctx workflow.Context, name string, argument, result any, options workflow.ActivityOptions) error {
	ctx, cancel := workflow.WithCancel(workflow.WithActivityOptions(ctx, options))
	defer cancel()
	future := workflow.ExecuteActivity(ctx, name, argument)
	expired := false
	selector := workflow.NewSelector(ctx)
	selector.AddFuture(future, func(workflow.Future) {})
	selector.AddFuture(workflow.NewTimer(ctx, options.ScheduleToCloseTimeout), func(workflow.Future) { expired = true })
	selector.Select(ctx)
	if expired {
		return safeRunError("PHASE_TIMEOUT")
	}
	return future.Get(ctx, result)
}

func canonicalBinding(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range []byte(value) {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}
