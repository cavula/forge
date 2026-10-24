package runs

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

type workflowFixture struct {
	mu     sync.Mutex
	record Record
	calls  []string
	hook   func(string, Ref) error
}

func (fixture *workflowFixture) call(name string, ref Ref) (Record, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.calls = append(fixture.calls, name)
	if ref.Validate() != nil {
		return Record{}, safeRunError("INTERNAL")
	}
	if fixture.hook != nil {
		if err := fixture.hook(name, ref); err != nil {
			return Record{}, err
		}
	}
	return fixture.record, nil
}

func (fixture *workflowFixture) environment() *testsuite.TestWorkflowEnvironment {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	for _, name := range []string{"Load", "Prepare", "GeneratePlan", "EvaluatePolicy", "ReadCommand"} {
		env.RegisterActivityWithOptions(func(_ context.Context, ref Ref) (Record, error) {
			return fixture.call(name, ref)
		}, activity.RegisterOptions{Name: name})
	}
	env.RegisterActivityWithOptions(func(_ context.Context, input TransitionInput) (Record, error) {
		fixture.mu.Lock()
		fixture.calls = append(fixture.calls, "Transition")
		fixture.record.Status = input.Next
		result := fixture.record
		fixture.mu.Unlock()
		return result, nil
	}, activity.RegisterOptions{Name: "Transition"})
	return env
}

func preparationWorkflow(ctx workflow.Context, input RunInput) (Record, error) {
	run := runExecution{input: input}
	err := run.prepare(ctx)
	return run.record, err
}

func TestPreparationRequiresManualApproval(t *testing.T) {
	fixture := workflowFixture{record: Record{Status: forgev1.RunStatus_RUN_STATUS_QUEUED}}
	env := fixture.environment()
	env.ExecuteWorkflow(preparationWorkflow, RunInput{OrgID: orgID, RunID: runID})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var result Record
	if err := env.GetWorkflowResult(&result); err != nil || result.Status != forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL {
		t.Fatalf("preparation result: %v", err)
	}
	want := []string{"Load", "Transition", "Prepare", "Transition", "GeneratePlan", "Transition", "EvaluatePolicy", "Transition"}
	if !reflect.DeepEqual(fixture.calls, want) {
		t.Fatalf("unexpected activity order: %v", fixture.calls)
	}
}

func TestPreparationPolicyFailuresDoNotAdvance(t *testing.T) {
	for _, code := range []string{"POLICY_DENIED", "POLICY_FAILED"} {
		t.Run(code, func(t *testing.T) {
			attempts := 0
			fixture := workflowFixture{record: Record{Status: forgev1.RunStatus_RUN_STATUS_QUEUED}}
			fixture.hook = func(name string, _ Ref) error {
				if name == "EvaluatePolicy" {
					attempts++
					return temporal.NewApplicationError(code, code)
				}
				return nil
			}
			env := fixture.environment()
			env.ExecuteWorkflow(preparationWorkflow, RunInput{OrgID: orgID, RunID: runID})
			if err := env.GetWorkflowError(); err == nil || runFailureCode(err, "INTERNAL") != code || attempts != 1 {
				t.Fatalf("policy failure not safely terminal: %v; attempts %d", err, attempts)
			}
			if fixture.record.Status != forgev1.RunStatus_RUN_STATUS_POLICY_CHECK {
				t.Fatal("failed policy advanced")
			}
		})
	}
}

func TestTemporalActivityBudgets(t *testing.T) {
	apply := runActivityOptions("ExecuteApply")
	if apply.RetryPolicy.MaximumAttempts != 1 || apply.ScheduleToCloseTimeout != time.Hour || !apply.WaitForCancellation {
		t.Fatal("apply permits retry launch or unbounded cancellation")
	}
	for _, name := range []string{"Load", "Transition", "Prepare", "GeneratePlan", "EvaluatePolicy", "StopAndReconcile", "Finish"} {
		options := runActivityOptions(name)
		if options.RetryPolicy.MaximumAttempts != 3 || options.StartToCloseTimeout <= 0 || options.ScheduleToCloseTimeout < options.StartToCloseTimeout {
			t.Fatalf("unbounded activity: %s", name)
		}
	}
	if runFailureCode(errors.New("raw credential diagnostic"), "PLAN_FAILED") != "PLAN_FAILED" ||
		runFailureCode(safeRunError("not-approved"), "PLAN_FAILED") != "INTERNAL" {
		t.Fatal("raw diagnostic escaped safe failure mapping")
	}
}
