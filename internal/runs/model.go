// Package runs defines metadata-only orchestration contracts. Validation checks
// structure; trusted adapters must independently authorize every persisted action.
package runs

import (
	"context"
	"errors"
	"strings"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
)

type RunStatus = forgev1.RunStatus

type RunInput struct{ OrgID, RunID string }
type RunResult struct {
	RunID       string
	Status      RunStatus
	FailureCode string
}
type Ref struct {
	RunInput
	OperationKey string
}
type Record struct {
	StackID, SnapshotID, ArtifactSetID, DecisionID, ApprovalID, ApplyJobID string
	ConfigurationRevision                                                  uint64
	Status                                                                 RunStatus
	BindingSHA256                                                          string
	CancellationRequested                                                  bool
}
type TransitionInput struct {
	Ref
	Expected, Next RunStatus
}
type ApplyInput struct {
	Ref
	BindingSHA256, ApprovalID string
}
type JobInput struct {
	Ref
	JobID string
}
type Outcome struct {
	EvidenceID           string
	Succeeded, Quiescent bool
}
type FinishInput struct {
	Ref
	Status                  RunStatus
	FailureCode, EvidenceID string
}

// Activities exchange references, never configuration, artifact or credential
// payloads. A DecisionID is a locator; BeginApply must reread trusted decisions.
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

var (
	ErrMetadata   = errors.New("invalid run metadata")
	ErrTransition = errors.New("invalid run transition")
)

// Validate does not establish the identity, tenant or authority of the sender.
func (in RunInput) Validate() error {
	if !canonicalUUID(in.OrgID) || !canonicalUUID(in.RunID) {
		return ErrMetadata
	}
	return nil
}

// NewRef deterministically names an activity's logical phase, independent of an
// execution attempt. Phase uses the exact existing protobuf enum name.
func NewRef(in RunInput, activity string, phase RunStatus) (Ref, error) {
	ref := Ref{RunInput: in, OperationKey: in.RunID + "/" + activity + "/" + phase.String()}
	if err := ref.Validate(); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

func (ref Ref) Validate() error {
	parts := strings.SplitN(ref.OperationKey, "/", 4)
	if ref.RunInput.Validate() != nil || len(parts) != 3 || parts[0] != ref.RunID {
		return ErrMetadata
	}
	switch parts[1] {
	case "Load", "Transition", "Prepare", "GeneratePlan", "EvaluatePolicy", "ReadCommand",
		"BeginApply", "ExecuteApply", "StopAndReconcile", "Finish":
	default:
		return ErrMetadata
	}
	number, ok := forgev1.RunStatus_value[parts[2]]
	if !ok || !iacStatus(RunStatus(number)) {
		return ErrMetadata
	}
	return nil
}

// ValidateFailureCode accepts empty for successful/nonfailure metadata; callers
// representing FAILED must additionally require a nonempty code.
func ValidateFailureCode(code string) error {
	switch code {
	case "", "PREPARE_FAILED", "PLAN_FAILED", "POLICY_DENIED", "POLICY_FAILED",
		"APPROVAL_TIMEOUT", "AUTHORIZATION_CHANGED", "STALE_BINDING", "PHASE_TIMEOUT",
		"APPLY_FAILED", "APPLY_OUTCOME_UNKNOWN", "INTERNAL":
		return nil
	default:
		return ErrMetadata
	}
}

func (result RunResult) Validate() error {
	if !canonicalUUID(result.RunID) || !terminal(result.Status) || ValidateFailureCode(result.FailureCode) != nil ||
		(result.Status == forgev1.RunStatus_RUN_STATUS_FAILED) != (result.FailureCode != "") {
		return ErrMetadata
	}
	return nil
}

// ValidateTransition checks only the IaC graph. In particular, a structurally
// valid NEEDS_APPROVAL -> APPLYING edge supplies no authority to execute it.
func ValidateTransition(from, to RunStatus) error {
	if !iacStatus(from) || !iacStatus(to) || terminal(from) {
		return ErrTransition
	}
	if to == forgev1.RunStatus_RUN_STATUS_FAILED || to == forgev1.RunStatus_RUN_STATUS_CANCELED {
		return nil
	}
	if from == forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL && to == forgev1.RunStatus_RUN_STATUS_DISCARDED {
		return nil
	}
	if to == from+1 && from >= forgev1.RunStatus_RUN_STATUS_QUEUED && from <= forgev1.RunStatus_RUN_STATUS_APPLYING {
		return nil
	}
	return ErrTransition
}

func iacStatus(status RunStatus) bool {
	return status >= forgev1.RunStatus_RUN_STATUS_QUEUED && status <= forgev1.RunStatus_RUN_STATUS_CANCELED
}

func terminal(status RunStatus) bool {
	return status >= forgev1.RunStatus_RUN_STATUS_FINISHED && status <= forgev1.RunStatus_RUN_STATUS_CANCELED
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, b := range []byte(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if b != '-' {
				return false
			}
		} else if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}
