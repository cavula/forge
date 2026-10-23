package runs

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

type workflowFixture struct {
	mu                  sync.Mutex
	record              Record
	calls               []string
	hook                func(string, Ref) error
	applied, reconciled Outcome
	beginBinding        string
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
	env.RegisterActivityWithOptions(func(_ context.Context, input ApplyInput) (Record, error) {
		fixture.mu.Lock()
		fixture.beginBinding = input.BindingSHA256
		fixture.mu.Unlock()
		if _, err := fixture.call("BeginApply", input.Ref); err != nil {
			return Record{}, err
		}
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		fixture.record.Status = forgev1.RunStatus_RUN_STATUS_APPLYING
		return fixture.record, nil
	}, activity.RegisterOptions{Name: "BeginApply"})
	env.RegisterActivityWithOptions(func(_ context.Context, input JobInput) (Outcome, error) {
		_, err := fixture.call("ExecuteApply", input.Ref)
		return fixture.applied, err
	}, activity.RegisterOptions{Name: "ExecuteApply"})
	env.RegisterActivityWithOptions(func(_ context.Context, ref Ref) (Outcome, error) {
		_, err := fixture.call("StopAndReconcile", ref)
		return fixture.reconciled, err
	}, activity.RegisterOptions{Name: "StopAndReconcile"})
	env.RegisterActivityWithOptions(func(_ context.Context, input FinishInput) (RunResult, error) {
		_, err := fixture.call("Finish", input.Ref)
		return RunResult{RunID: input.RunID, Status: input.Status, FailureCode: input.FailureCode}, err
	}, activity.RegisterOptions{Name: "Finish"})
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

func newRunFixture() *workflowFixture {
	return &workflowFixture{record: Record{Status: forgev1.RunStatus_RUN_STATUS_QUEUED,
		DecisionID: orgID, ApplyJobID: runID, BindingSHA256: strings.Repeat("a", 64)},
		applied:    Outcome{EvidenceID: runID, Succeeded: true, Quiescent: true},
		reconciled: Outcome{EvidenceID: orgID, Quiescent: true}}
}

func runWorkflowResult(t *testing.T, env *testsuite.TestWorkflowEnvironment) RunResult {
	t.Helper()
	env.ExecuteWorkflow(RunWorkflow, RunInput{OrgID: orgID, RunID: runID})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var result RunResult
	if err := env.GetWorkflowResult(&result); err != nil || result.Validate() != nil {
		t.Fatalf("invalid workflow result: %v", err)
	}
	return result
}

func TestRunWorkflowManualCommandRereads(t *testing.T) {
	var previous []string
	for attempt := 0; attempt < 2; attempt++ {
		fixture := newRunFixture()
		env := fixture.environment()
		env.RegisterDelayedCallback(func() {
			env.SignalWorkflow("run-command", map[string]string{"org_id": orgID, "approval_id": runID})
		}, time.Minute)
		env.RegisterDelayedCallback(func() {
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			for _, name := range fixture.calls {
				if name == "BeginApply" || name == "ExecuteApply" {
					t.Error("signal payload bypassed durable human approval")
				}
			}
			fixture.record.ApprovalID = runID
			env.SignalWorkflow("run-command", runID)
		}, 2*time.Minute)
		if result := runWorkflowResult(t, env); result.Status != forgev1.RunStatus_RUN_STATUS_FINISHED {
			t.Fatalf("normal result: %v", result)
		}
		if previous != nil && !reflect.DeepEqual(previous, fixture.calls) {
			t.Fatal("same durable command history changed activity order")
		}
		previous = append([]string(nil), fixture.calls...)
	}
}

func TestRunWorkflowStaleApprovalAndLostAcknowledgment(t *testing.T) {
	for _, stale := range []bool{true, false} {
		fixture := newRunFixture()
		fixture.reconciled = Outcome{}
		fixture.hook = func(name string, _ Ref) error {
			if name == "ReadCommand" && fixture.record.Status == forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL {
				fixture.record.ApprovalID = runID
				if stale {
					fixture.record.BindingSHA256 = strings.Repeat("b", 64)
				}
			}
			if stale && name == "BeginApply" {
				fixture.reconciled = Outcome{EvidenceID: orgID, Quiescent: true}
				return safeRunError("STALE_BINDING")
			}
			if name == "ExecuteApply" {
				return errors.New("lost acknowledgment with private diagnostics")
			}
			return nil
		}
		result := runWorkflowResult(t, fixture.environment())
		want, applies := "APPLY_OUTCOME_UNKNOWN", 0
		if stale {
			want = "STALE_BINDING"
		}
		for _, name := range fixture.calls {
			if name == "ExecuteApply" {
				applies++
			}
		}
		if result.FailureCode != want || fixture.beginBinding != strings.Repeat("a", 64) || (stale && applies != 0) || (!stale && applies != 1) {
			t.Fatalf("unsafe binding/retry result: %v, applies %d", result, applies)
		}
	}
}

func TestIndependentApprovalDeadlineDuringJournalRead(t *testing.T) {
	fixture := newRunFixture()
	env := fixture.environment()
	approvalRead := mock.MatchedBy(func(ref Ref) bool {
		return strings.HasSuffix(ref.OperationKey, "/ReadCommand/RUN_STATUS_NEEDS_APPROVAL")
	})
	env.OnActivity("ReadCommand", mock.Anything, approvalRead).Return(Record{}, nil).Once()
	env.OnActivity("ReadCommand", mock.Anything, approvalRead).After(90*time.Second).Return(Record{ApprovalID: runID}, nil).Once()
	env.OnActivity("ReadCommand", mock.Anything, mock.Anything).Return(func(_ context.Context, ref Ref) (Record, error) { return fixture.call("ReadCommand", ref) })
	env.RegisterDelayedCallback(func() { env.SignalWorkflow("run-command", runID) }, 23*time.Hour+59*time.Minute)
	result := runWorkflowResult(t, env)
	if result.Status != forgev1.RunStatus_RUN_STATUS_FAILED || result.FailureCode != "APPROVAL_TIMEOUT" {
		t.Fatalf("approval arriving after the24h deadline was accepted: result=%v calls=%v", result, fixture.calls)
	}
}

func TestIndependentRejectMissingSuccessEvidence(t *testing.T) {
	fixture := newRunFixture()
	approveFixture(fixture)
	fixture.applied = Outcome{Succeeded: true, Quiescent: true}
	result := runWorkflowResult(t, fixture.environment())
	if result.Status == forgev1.RunStatus_RUN_STATUS_FINISHED {
		t.Fatalf("successful finish accepted without evidence UUID: %v", result)
	}
}

func TestIndependentRejectInvalidApprovalID(t *testing.T) {
	fixture := newRunFixture()
	fixture.hook = func(name string, _ Ref) error {
		if name == "ReadCommand" && fixture.record.Status == forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL {
			fixture.record.ApprovalID = "credential=must-not-enter-history"
		}
		return nil
	}
	result := runWorkflowResult(t, fixture.environment())
	for _, name := range fixture.calls {
		if name == "BeginApply" || name == "ExecuteApply" {
			t.Fatalf("malformed approval reference reached admission/apply: %v calls=%v", result, fixture.calls)
		}
	}
}

func TestIndependentRejectSuccessAfterAdmissionDenial(t *testing.T) {
	fixture := newRunFixture()
	approveFixture(fixture)
	approve := fixture.hook
	fixture.hook = func(name string, ref Ref) error {
		if name == "BeginApply" {
			return safeRunError("STALE_BINDING")
		}
		return approve(name, ref)
	}
	fixture.reconciled = Outcome{EvidenceID: orgID, Succeeded: true, Quiescent: true}
	result := runWorkflowResult(t, fixture.environment())
	if result.Status == forgev1.RunStatus_RUN_STATUS_FINISHED {
		t.Fatalf("admission denial became success without ExecuteApply: %v calls=%v", result, fixture.calls)
	}
}

func approveFixture(fixture *workflowFixture) {
	fixture.hook = func(name string, _ Ref) error {
		if name == "ReadCommand" && fixture.record.Status == forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL {
			fixture.record.ApprovalID = runID
		}
		return nil
	}
}
