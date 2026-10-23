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

func approveFixture(fixture *workflowFixture) {
	fixture.hook = func(name string, _ Ref) error {
		if name == "ReadCommand" && fixture.record.Status == forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL {
			fixture.record.ApprovalID = runID
		}
		return nil
	}
}

func TestRunWorkflowCancellationAtEveryPhase(t *testing.T) {
	for _, phase := range []string{"Load", "Prepare", "GeneratePlan", "EvaluatePolicy", "Approval", "BeginApply", "ExecuteApply"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newRunFixture()
			if phase != "Approval" {
				approveFixture(fixture)
			}
			env := fixture.environment()
			if phase != "Approval" {
				call := env.OnActivity(phase, mock.Anything, mock.Anything).After(time.Hour)
				if phase == "ExecuteApply" {
					call.Return(Outcome{}, nil)
				} else {
					call.Return(Record{}, nil)
				}
			}
			env.RegisterDelayedCallback(env.CancelWorkflow, time.Second)
			if result := runWorkflowResult(t, env); result.Status != forgev1.RunStatus_RUN_STATUS_CANCELED {
				t.Fatalf("cancel result: %v", result)
			}
			if fixture.calls[len(fixture.calls)-2] != "StopAndReconcile" || fixture.calls[len(fixture.calls)-1] != "Finish" {
				t.Fatal("cancellation skipped quiescence evidence")
			}
		})
	}
}

func TestRunWorkflowCommandsRequireQuiescence(t *testing.T) {
	for _, quiescent := range []bool{false, true} {
		fixture := newRunFixture()
		approveFixture(fixture)
		fixture.reconciled = Outcome{EvidenceID: runID, Quiescent: quiescent}
		env := fixture.environment()
		env.OnActivity("ExecuteApply", mock.Anything, mock.Anything).After(time.Hour).Return(Outcome{}, nil)
		env.RegisterDelayedCallback(func() {
			fixture.mu.Lock()
			fixture.record.CancellationRequested = true
			fixture.mu.Unlock()
			env.SignalWorkflow("run-command", map[string]string{"command": "cancel"})
		}, time.Second)
		result := runWorkflowResult(t, env)
		if (quiescent && result.Status != forgev1.RunStatus_RUN_STATUS_CANCELED) ||
			(!quiescent && result.FailureCode != "APPLY_OUTCOME_UNKNOWN") {
			t.Fatalf("quiescence did not govern cancellation: %v", result)
		}
	}
	fixture := newRunFixture()
	fixture.hook = func(name string, _ Ref) error {
		if name == "ReadCommand" && fixture.record.Status == forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL {
			fixture.record.Status = forgev1.RunStatus_RUN_STATUS_DISCARDED
		}
		return nil
	}
	if result := runWorkflowResult(t, fixture.environment()); result.Status != forgev1.RunStatus_RUN_STATUS_DISCARDED {
		t.Fatalf("discard result: %v", result)
	}
}

func TestRunWorkflowFailureAndRetryLimits(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		fixture, attempts := newRunFixture(), 0
		fixture.hook = func(name string, _ Ref) error {
			if name == "Prepare" {
				attempts++
				if permanent {
					return temporal.NewApplicationError("PREPARE_FAILED", "PREPARE_FAILED")
				}
				return errors.New("transient transport failure")
			}
			return nil
		}
		result := runWorkflowResult(t, fixture.environment())
		if result.FailureCode != "PREPARE_FAILED" || (permanent && attempts != 1) || (!permanent && attempts != 3) {
			t.Fatalf("retry budget: %v; attempts %d", result, attempts)
		}
	}
	for _, code := range []string{"POLICY_DENIED", "POLICY_FAILED", "AUTHORIZATION_CHANGED"} {
		fixture := newRunFixture()
		approveFixture(fixture)
		approve := fixture.hook
		fixture.hook = func(name string, ref Ref) error {
			if (code != "AUTHORIZATION_CHANGED" && name == "EvaluatePolicy") || (code == "AUTHORIZATION_CHANGED" && name == "BeginApply") {
				return safeRunError(code)
			}
			return approve(name, ref)
		}
		result := runWorkflowResult(t, fixture.environment())
		if result.FailureCode != code || strings.Contains(strings.Join(fixture.calls, ","), "ExecuteApply") {
			t.Fatalf("failure bypassed admission: %v", result)
		}
	}
}

func TestRunWorkflowApprovalTimeoutAndMalformedMetadata(t *testing.T) {
	fixture := newRunFixture()
	if result := runWorkflowResult(t, fixture.environment()); result.FailureCode != "APPROVAL_TIMEOUT" {
		t.Fatalf("approval wait was not finite: %v", result)
	}
	for _, binding := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		fixture := newRunFixture()
		fixture.record.BindingSHA256 = binding
		if result := runWorkflowResult(t, fixture.environment()); result.FailureCode != "POLICY_FAILED" {
			t.Fatalf("malformed trusted metadata reached approval: %v", result)
		}
	}
}

func deadlineWorkflow(ctx workflow.Context, input RunInput) error {
	run := runExecution{input: input, record: Record{Status: forgev1.RunStatus_RUN_STATUS_PREPARING},
		signals: workflow.GetSignalChannel(ctx, "run-command"), deadline: workflow.NewTimer(ctx, time.Second)}
	return run.callRecord(ctx, "Prepare", run.ref("Prepare"))
}

func TestWorkflowSafetyDeadline(t *testing.T) {
	fixture := newRunFixture()
	env := fixture.environment()
	env.OnActivity("Prepare", mock.Anything, mock.Anything).After(time.Minute).Return(Record{}, nil)
	env.ExecuteWorkflow(deadlineWorkflow, RunInput{OrgID: orgID, RunID: runID})
	if err := env.GetWorkflowError(); err == nil || runFailureCode(err, "INTERNAL") != "PHASE_TIMEOUT" {
		t.Fatalf("workflow timer failed: %v", err)
	}
}

func TestRunWorkflowPhaseTimeoutAndCleanupFailure(t *testing.T) {
	fixture := newRunFixture()
	env := fixture.environment()
	env.OnActivity("EvaluatePolicy", mock.Anything, mock.Anything).After(time.Minute).Return(fixture.record, nil)
	if result := runWorkflowResult(t, env); result.FailureCode != "PHASE_TIMEOUT" {
		t.Fatalf("phase timeout failed: %v", result)
	}
	fixture = newRunFixture()
	approveFixture(fixture)
	approve := fixture.hook
	fixture.hook = func(name string, ref Ref) error {
		if name == "ExecuteApply" || name == "StopAndReconcile" {
			return safeRunError("INTERNAL")
		}
		return approve(name, ref)
	}
	if result := runWorkflowResult(t, fixture.environment()); result.FailureCode != "APPLY_OUTCOME_UNKNOWN" {
		t.Fatalf("failed reconciliation released uncertainty: %v", result)
	}
}

func TestRunWorkflowCleanupDeadlines(t *testing.T) {
	fixture := newRunFixture()
	approveFixture(fixture)
	env := fixture.environment()
	env.OnActivity("ExecuteApply", mock.Anything, mock.Anything).Return(Outcome{}, safeRunError("APPLY_FAILED"))
	env.OnActivity("StopAndReconcile", mock.Anything, mock.Anything).After(time.Hour).Return(Outcome{}, nil)
	if result := runWorkflowResult(t, env); result.FailureCode != "APPLY_OUTCOME_UNKNOWN" {
		t.Fatalf("cleanup timeout bypassed quarantine: %v", result)
	}
	fixture = newRunFixture()
	approveFixture(fixture)
	env = fixture.environment()
	env.OnActivity("Finish", mock.Anything, mock.Anything).After(time.Hour).Return(RunResult{}, nil)
	env.ExecuteWorkflow(RunWorkflow, RunInput{OrgID: orgID, RunID: runID})
	if err := env.GetWorkflowError(); err == nil || runFailureCode(err, "APPLY_FAILED") != "INTERNAL" {
		t.Fatalf("uncertain finalization did not fail safely: %v", err)
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

func TestIndependentSafetyRepeatedForgedSignalsDoNotRelaunch(t *testing.T) {
	fixture := newRunFixture()
	approveFixture(fixture)
	env := fixture.environment()
	applies := 0
	env.OnActivity("ExecuteApply", mock.Anything, mock.Anything).After(20 * time.Second).Return(func(_ context.Context, _ JobInput) (Outcome, error) { applies++; return fixture.applied, nil }).Once()
	for second := 1; second <= 10; second++ {
		env.RegisterDelayedCallback(func() {
			env.SignalWorkflow("run-command", map[string]string{"approval": "forged", "org": "foreign", "status": "FINISHED"})
		}, time.Duration(second)*time.Second)
	}
	result := runWorkflowResult(t, env)
	if result.Status != forgev1.RunStatus_RUN_STATUS_FINISHED || applies != 1 || fixture.beginBinding != strings.Repeat("a", 64) {
		t.Fatalf("signal altered apply/binding: %v count=%d", result, applies)
	}
}

func TestIndependentSafetyForgedApprovalNeverEntersApply(t *testing.T) {
	fixture := newRunFixture()
	env := fixture.environment()
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow("run-command", map[string]string{"ApprovalID": runID, "BindingSHA256": strings.Repeat("a", 64)})
	}, time.Second)
	result := runWorkflowResult(t, env)
	if result.FailureCode != "APPROVAL_TIMEOUT" {
		t.Fatalf("forged approval changed wait outcome: %v", result)
	}
	for _, name := range fixture.calls {
		if name == "BeginApply" || name == "ExecuteApply" {
			t.Fatal("signal granted admission")
		}
	}
}

func TestIndependentSafetyRejectInvalidFinishMetadata(t *testing.T) {
	for _, result := range []RunResult{{RunID: orgID, Status: forgev1.RunStatus_RUN_STATUS_FINISHED}, {RunID: runID, Status: RunStatus(2147483647)}, {RunID: runID, Status: forgev1.RunStatus_RUN_STATUS_FAILED, FailureCode: "raw credential diagnostic"}} {
		fixture := newRunFixture()
		approveFixture(fixture)
		env := fixture.environment()
		env.OnActivity("Finish", mock.Anything, mock.Anything).Return(result, nil)
		env.ExecuteWorkflow(RunWorkflow, RunInput{OrgID: orgID, RunID: runID})
		if err := env.GetWorkflowError(); err == nil || runFailureCode(err, "APPLY_FAILED") != "INTERNAL" || strings.Contains(err.Error(), "raw credential") {
			t.Fatalf("invalid Finish metadata escaped: %v", err)
		}
	}
}
