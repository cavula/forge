package runs

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
)

const orgID = "5b08ba72-4323-4621-92a5-97869ea09a10"
const runID = "fae0d487-ab8c-4455-87de-c2443ee6a293"

func TestIaCTransitions(t *testing.T) {
	path := []RunStatus{forgev1.RunStatus_RUN_STATUS_QUEUED, forgev1.RunStatus_RUN_STATUS_PREPARING,
		forgev1.RunStatus_RUN_STATUS_PLANNING, forgev1.RunStatus_RUN_STATUS_POLICY_CHECK,
		forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL, forgev1.RunStatus_RUN_STATUS_APPLYING,
		forgev1.RunStatus_RUN_STATUS_FINISHED}
	for i := 0; i < len(path)-1; i++ {
		if err := ValidateTransition(path[i], path[i+1]); err != nil {
			t.Fatalf("normal edge %v: %v", path[i], err)
		}
		for _, stop := range []RunStatus{forgev1.RunStatus_RUN_STATUS_FAILED, forgev1.RunStatus_RUN_STATUS_CANCELED} {
			if err := ValidateTransition(path[i], stop); err != nil {
				t.Fatalf("terminal edge %v -> %v: %v", path[i], stop, err)
			}
		}
	}
	if err := ValidateTransition(forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL, forgev1.RunStatus_RUN_STATUS_DISCARDED); err != nil {
		t.Fatal(err)
	}
	bad := [][2]RunStatus{
		{forgev1.RunStatus_RUN_STATUS_QUEUED, forgev1.RunStatus_RUN_STATUS_APPLYING},
		{forgev1.RunStatus_RUN_STATUS_PLANNING, forgev1.RunStatus_RUN_STATUS_FINISHED},
		{forgev1.RunStatus_RUN_STATUS_APPLYING, forgev1.RunStatus_RUN_STATUS_DISCARDED},
		{forgev1.RunStatus_RUN_STATUS_NEEDS_APPROVAL, forgev1.RunStatus_RUN_STATUS_PLANNING},
		{forgev1.RunStatus_RUN_STATUS_QUEUED, forgev1.RunStatus_RUN_STATUS_QUEUED},
	}
	for _, pair := range bad {
		if !errors.Is(ValidateTransition(pair[0], pair[1]), ErrTransition) {
			t.Fatalf("illegal edge accepted: %v", pair)
		}
	}
	for from := RunStatus(-1); from <= 19; from++ {
		for to := RunStatus(-1); to <= 19; to++ {
			if (from < 1 || from > 10 || to < 1 || to > 10 || from >= 7) && ValidateTransition(from, to) == nil {
				t.Fatalf("unknown/terminal edge accepted: %v -> %v", from, to)
			}
		}
	}
}

func TestCanonicalReferences(t *testing.T) {
	in := RunInput{OrgID: orgID, RunID: runID}
	first, err := NewRef(in, "GeneratePlan", forgev1.RunStatus_RUN_STATUS_PLANNING)
	if err != nil || first.OperationKey != runID+"/GeneratePlan/RUN_STATUS_PLANNING" {
		t.Fatalf("canonical reference: %v", err)
	}
	second, err := NewRef(in, "GeneratePlan", forgev1.RunStatus_RUN_STATUS_PLANNING)
	if err != nil || first != second {
		t.Fatal("reference changed across attempts")
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("metadata encoding changed")
	}
	for _, invalid := range []string{"", strings.ToUpper(orgID), "00000000-0000-0000-0000-000000000000", " " + orgID,
		orgID + "\n", strings.ReplaceAll(orgID, "-", ""), "https://example.test/token", orgID[:35] + "/"} {
		for _, value := range []RunInput{{OrgID: invalid, RunID: runID}, {OrgID: orgID, RunID: invalid}} {
			if !errors.Is(value.Validate(), ErrMetadata) {
				t.Fatal("malformed identity accepted")
			}
		}
	}
	for _, key := range []string{runID + "/Prepare/PLANNING", runID + "/Prepare/RUN_STATUS_PREVIEW",
		runID + "/Prepare/999", runID + "/Shell/RUN_STATUS_PLANNING", runID + "/Prepare/RUN_STATUS_PLANNING/extra",
		orgID + "/Prepare/RUN_STATUS_PLANNING", first.OperationKey + "\n", ""} {
		if !errors.Is((Ref{RunInput: in, OperationKey: key}).Validate(), ErrMetadata) {
			t.Fatal("malformed operation key accepted")
		}
	}
	if ref, err := NewRef(in, "Prepare", RunStatus(999)); !errors.Is(err, ErrMetadata) || ref != (Ref{}) {
		t.Fatal("unknown phase returned a reference")
	}
}

func TestResultFailureCodesAreSanitized(t *testing.T) {
	for _, code := range strings.Fields("PREPARE_FAILED PLAN_FAILED POLICY_DENIED POLICY_FAILED APPROVAL_TIMEOUT AUTHORIZATION_CHANGED STALE_BINDING PHASE_TIMEOUT APPLY_FAILED APPLY_OUTCOME_UNKNOWN INTERNAL") {
		if err := (RunResult{RunID: runID, Status: forgev1.RunStatus_RUN_STATUS_FAILED, FailureCode: code}).Validate(); err != nil {
			t.Fatalf("fixed failure code: %v", err)
		}
	}
	for _, status := range []RunStatus{forgev1.RunStatus_RUN_STATUS_FINISHED, forgev1.RunStatus_RUN_STATUS_DISCARDED, forgev1.RunStatus_RUN_STATUS_CANCELED} {
		if err := (RunResult{RunID: runID, Status: status}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	secret := "credential=must-never-appear"
	bad := []RunResult{
		{RunID: runID, Status: forgev1.RunStatus_RUN_STATUS_FAILED},
		{RunID: runID, Status: forgev1.RunStatus_RUN_STATUS_FAILED, FailureCode: secret},
		{RunID: runID, Status: forgev1.RunStatus_RUN_STATUS_FINISHED, FailureCode: "INTERNAL"},
		{RunID: runID, Status: forgev1.RunStatus_RUN_STATUS_APPLYING},
		{RunID: "wrong", Status: forgev1.RunStatus_RUN_STATUS_CANCELED},
		{RunID: runID, Status: RunStatus(999)},
	}
	for _, result := range bad {
		err := result.Validate()
		if !errors.Is(err, ErrMetadata) || strings.Contains(err.Error(), secret) {
			t.Fatal("invalid result or sensitive diagnostic accepted")
		}
	}
}

func TestActivityMetadataContainsOnlyReferences(t *testing.T) {
	allowed := strings.Fields("OrgID RunID OperationKey StackID SnapshotID ArtifactSetID DecisionID ApprovalID ApplyJobID ConfigurationRevision Status BindingSHA256 CancellationRequested Expected Next JobID EvidenceID Succeeded Quiescent FailureCode")
	var check func(reflect.Type)
	check = func(typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Anonymous {
				check(field.Type)
				continue
			}
			found := false
			for _, name := range allowed {
				found = found || field.Name == name
			}
			kind := field.Type.Kind()
			if !found || (kind != reflect.String && kind != reflect.Int32 && kind != reflect.Uint64 && kind != reflect.Bool) {
				t.Fatalf("unreviewed payload field: %v.%s", typ.Name(), field.Name)
			}
		}
	}
	for _, value := range []any{RunInput{}, RunResult{}, Ref{}, Record{}, TransitionInput{}, ApplyInput{}, JobInput{}, Outcome{}, FinishInput{}} {
		check(reflect.TypeOf(value))
	}
}
