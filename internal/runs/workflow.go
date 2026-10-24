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
				"AUTHORIZATION_CHANGED", "STALE_BINDING", "INTERNAL"}}}
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
	input  RunInput
	record Record
}

func (run *runExecution) ref(name string) Ref {
	ref, _ := NewRef(run.input, name, run.record.Status)
	return ref
}

func (run *runExecution) callRecord(ctx workflow.Context, name string, argument any) error {
	ctx = workflow.WithActivityOptions(ctx, runActivityOptions(name))
	return workflow.ExecuteActivity(ctx, name, argument).Get(ctx, &run.record)
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
