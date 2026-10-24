package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cavula/forge/internal/testutil"
)

func evaluator(t *testing.T) *Evaluator {
	t.Helper()
	e, err := NewEvaluator(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Native show-json shape: computed fields unrelated to controls stay permitted.
func planFixture(kind string, after any, actions []string) []byte {
	plan, _ := json.Marshal(map[string]any{"format_version": "1.2", "planned_values": map[string]any{},
		"resource_changes": []any{map[string]any{"address": "fixture.sensitive-address", "mode": "managed", "type": kind,
			"change": map[string]any{"actions": actions, "after": after, "after_unknown": map[string]any{"id": true}}}}})
	return plan
}

func TestEmbeddedStarterDecisions(t *testing.T) {
	e := evaluator(t)
	for _, tc := range []struct {
		kind, field string
		value       any
		id          string
	}{
		{"aws_vpc_security_group_ingress_rule", "cidr_ipv6", "0:0:0:0:0:0:0:0/0", "FORGE-001"},
		{"aws_ebs_volume", "encrypted", false, "FORGE-002"},
		{"aws_db_instance", "publicly_accessible", true, "FORGE-003"},
		{"aws_db_instance", "storage_encrypted", false, "FORGE-004"},
		{"aws_s3_bucket_acl", "acl", "public-read", "FORGE-005"},
		{"aws_instance", "metadata_options", []any{map[string]any{"http_tokens": "optional"}}, "FORGE-006"},
		{"aws_db_instance", "backup_retention_period", 0, "FORGE-007"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()
			plan := planFixture(tc.kind, map[string]any{tc.field: tc.value}, []string{"create"})
			d, err := e.Evaluate(context.Background(), plan, sha256.Sum256(plan))
			if err != nil || d.Allowed || !strings.Contains(strings.Join(d.Deny, ","), tc.id) {
				t.Fatal("control did not deny")
			}
		})
	}
	for _, tc := range []struct {
		kind           string
		after          any
		actions        []string
		approval, warn []string
	}{
		{"aws_ebs_volume", map[string]any{"encrypted": true, "tags": map[string]any{"owner": "fixture"}}, []string{"create"}, []string{}, []string{}},
		{"aws_iam_role", map[string]any{"name": "fixture-sensitive-value"}, []string{"delete", "create"}, []string{"FORGE-008", "FORGE-009"}, []string{}},
		{"aws_ebs_volume", nil, []string{"delete"}, []string{"FORGE-008"}, []string{}},
		{"aws_s3_bucket", map[string]any{}, []string{"create"}, []string{}, []string{"FORGE-010"}},
	} {
		plan := planFixture(tc.kind, tc.after, tc.actions)
		hash := sha256.Sum256(plan)
		d, err := e.Evaluate(context.Background(), plan, hash)
		if err != nil || !d.Allowed || d.PlanSHA256 != hash || !reflect.DeepEqual(d.Approval, tc.approval) || !reflect.DeepEqual(d.Warn, tc.warn) || d.RequiresApproval != (len(tc.approval) > 0) {
			t.Fatal("incorrect plan decision")
		}
		testutil.NoSecrets(t, fmt.Sprint(d), "fixture-sensitive-value", "fixture.sensitive-address")
	}
	for _, plan := range []string{`{}`, `null`, `[]`, `{"format_version":"2.0","planned_values":{}}`, `{"format_version":"1.2","planned_values":{},"resource_changes":[{}]}`} {
		d, err := e.Evaluate(context.Background(), []byte(plan), sha256.Sum256([]byte(plan)))
		if err != nil || d.Allowed || !reflect.DeepEqual(d.Deny, []string{"FORGE-PLAN-INVALID"}) {
			t.Fatal("invalid plan accepted")
		}
	}
}

func TestEvaluationFailuresAndPlanBinding(t *testing.T) {
	e := evaluator(t)
	valid := []byte(`{"format_version":"1.2","planned_values":{}}`)
	for _, plan := range [][]byte{nil, []byte(`{"secret":"fixture-sensitive-value"`), append(append([]byte{}, valid...), []byte(` {}`)...), []byte(`{"format_version":"1.2","format_version":"1.2"}`), []byte(strings.Repeat("[", 66) + strings.Repeat("]", 66)), make([]byte, MaxPlanBytes+1), []byte(`{"value":1e999999999}`), []byte(`{"value":1e-999999999}`), []byte(`{"value":0.` + strings.Repeat("1", 257) + `}`)} {
		d, err := e.Evaluate(context.Background(), plan, sha256.Sum256(plan))
		if !errors.Is(err, ErrEvaluation) || d.Allowed {
			t.Fatal("failed input accepted")
		}
		testutil.NoSecrets(t, fmt.Sprint(err, d), "fixture-sensitive-value")
	}
	for _, candidate := range []*Evaluator{nil, {}, e} {
		d, err := candidate.Evaluate(context.Background(), valid, sha256.Sum256([]byte("different artifact")))
		if !errors.Is(err, ErrEvaluation) || d.Allowed {
			t.Fatal("unbound or unprepared input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Evaluate(ctx, valid, sha256.Sum256(valid)); !errors.Is(err, ErrEvaluation) {
		t.Fatal("cancellation ignored")
	}
	if _, err := NewEvaluator(ctx); !errors.Is(err, ErrEvaluation) {
		t.Fatal("startup cancellation ignored")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := e.Evaluate(ctx, valid, sha256.Sum256(valid)); !errors.Is(err, ErrEvaluation) {
		t.Fatal("deadline ignored")
	}
}

func TestMalformedUTF8Plan(t *testing.T) {
	plan := []byte("{\"format_version\":\"1.2\",\"planned_values\":{\"value\":\"\xff\"}}")
	d, err := evaluator(t).Evaluate(context.Background(), plan, sha256.Sum256(plan))
	if !errors.Is(err, ErrEvaluation) || d.Allowed {
		t.Fatal("non-UTF8 plan accepted despite matching artifact hash")
	}
}

func TestEvaluatorRejectsUndefinedErrorsAndCapabilities(t *testing.T) {
	for _, source := range []string{
		`package forge.plan
decision if false`,
		`package forge.plan
decision := net.cidr_contains(input.zero, "0.0.0.0/0")`,
		`package forge.plan
decision := {"allowed":true,"requires_approval":false,"deny":[],"warn":[],"approval":["FORGE-009"]}`,
	} {
		e, err := prepare(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		plan := []byte(`{"zero":0}`)
		d, err := e.Evaluate(context.Background(), plan, sha256.Sum256(plan))
		if !errors.Is(err, ErrEvaluation) || d.Allowed {
			t.Fatal("undefined, error or inconsistent decision accepted")
		}
	}
	for _, body := range []string{`http.send({"url":"https://fixture.invalid"})`, `time.now_ns()`, `print("fixture-sensitive-value")`, `invalid(`} {
		if _, err := prepare(context.Background(), "package forge.plan\ndecision := "+body); !errors.Is(err, ErrEvaluation) {
			t.Fatal("forbidden capability accepted")
		}
	}
}

func TestDecisionValidation(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{"allowed": true, "requires_approval": false, "deny": []any{}, "warn": []any{}, "approval": []any{}}
	}
	for _, value := range []any{nil, true, map[string]any{}, map[string]any{"unexpected": true}} {
		if _, err := decodeDecision(value); err == nil {
			t.Fatal("invalid decision shape accepted")
		}
	}
	for _, invalid := range []any{nil, []any{"UNKNOWN"}, []any{1}, []any{"FORGE-010", "FORGE-010"}, []any{"FORGE-009"}, make([]any, 9)} {
		value := valid()
		value["warn"] = invalid
		if _, err := decodeDecision(value); err == nil {
			t.Fatal("invalid rule IDs accepted")
		}
	}
	value := valid()
	value["allowed"] = false
	if _, err := decodeDecision(value); err == nil {
		t.Fatal("inconsistent allowed result accepted")
	}
}
