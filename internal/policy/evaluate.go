// Package policy evaluates immutable saved plans against embedded starter rules.
package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cavula/forge/policies"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

const MaxPlanBytes = 1 << 20
const evaluationTimeout = time.Second

// ErrEvaluation deliberately contains no input, resource values or SDK diagnostics.
var ErrEvaluation = errors.New("policy evaluation failed")

// Decision never grants authority to apply; the run must enforce human approval.
type Decision struct {
	PlanSHA256                [32]byte
	Deny, Warn, Approval      []string
	Allowed, RequiresApproval bool
}

type Evaluator struct {
	query rego.PreparedEvalQuery
	ready bool
}

// NewEvaluator compiles the reviewed query once during application startup.
func NewEvaluator(ctx context.Context) (*Evaluator, error) {
	return prepare(ctx, policies.Starter())
}

func prepare(ctx context.Context, source string) (*Evaluator, error) {
	ctx, cancel := context.WithTimeout(ctx, evaluationTimeout)
	defer cancel()
	caps := ast.CapabilitiesForThisVersion()
	allowed := strings.Fields("eq equal neq gt gte count sort walk startswith regex.match object.get net.cidr_is_valid net.cidr_contains is_object is_array is_string is_boolean is_number internal.member_2 internal.member_3")
	caps.Builtins = slices.DeleteFunc(caps.Builtins, func(b *ast.Builtin) bool { return !slices.Contains(allowed, b.Name) })
	caps.AllowNet = []string{}
	query, err := rego.New(rego.Query("data.forge.plan.decision"), rego.Module("starter.rego", source),
		rego.Capabilities(caps), rego.Strict(true), rego.StrictBuiltinErrors(true)).PrepareForEval(ctx)
	if err != nil || ctx.Err() != nil {
		return nil, ErrEvaluation
	}
	return &Evaluator{query: query, ready: true}, nil
}

// Evaluate binds the decision to exactly these saved-plan JSON bytes. trustedHash
// must come from trusted artifact storage, never a request-provided digest.
func (e *Evaluator) Evaluate(ctx context.Context, savedPlan []byte, trustedHash [32]byte) (Decision, error) {
	if e == nil || !e.ready || len(savedPlan) == 0 || len(savedPlan) > MaxPlanBytes || ctx.Err() != nil {
		return Decision{}, ErrEvaluation
	}
	ctx, cancel := context.WithTimeout(ctx, evaluationTimeout)
	defer cancel()
	plan := bytes.Clone(savedPlan)
	if sha256.Sum256(plan) != trustedHash || !utf8.Valid(plan) {
		return Decision{}, ErrEvaluation
	}
	decoder := json.NewDecoder(bytes.NewReader(plan))
	decoder.UseNumber()
	input, err := readJSON(decoder, 0)
	if err != nil {
		return Decision{}, ErrEvaluation
	}
	if _, err = decoder.Token(); err != io.EOF || ctx.Err() != nil {
		return Decision{}, ErrEvaluation
	}
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil || ctx.Err() != nil || len(results) != 1 || len(results[0].Expressions) != 1 {
		return Decision{}, ErrEvaluation
	}
	decision, err := decodeDecision(results[0].Expressions[0].Value)
	if err != nil {
		return Decision{}, ErrEvaluation
	}
	decision.PlanSHA256 = trustedHash
	return decision, nil
}

// readJSON rejects duplicate keys and excessive nesting rather than accepting
// a plan whose interpretation could differ between components.
func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrEvaluation
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if _, duplicate := object[name]; !ok || duplicate {
				return nil, ErrEvaluation
			}
			value, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		_, err := d.Token()
		return object, err
	case json.Delim('['):
		array := []any{}
		for d.More() {
			value, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := d.Token()
		return array, err
	default:
		if number, ok := token.(json.Number); ok {
			// Keep exact digits while rejecting pathological precision/exponents
			// before the SDK converts numbers to arbitrary-precision values.
			if _, err := number.Float64(); err != nil || len(number) > 256 {
				return nil, ErrEvaluation
			}
			if at := strings.IndexAny(string(number), "eE"); at >= 0 {
				if exponent, err := strconv.Atoi(string(number)[at+1:]); err != nil || exponent < -308 || exponent > 308 {
					return nil, ErrEvaluation
				}
			}
		}
		return token, nil
	}
}

func decodeDecision(value any) (Decision, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 5 {
		return Decision{}, ErrEvaluation
	}
	allowed, aOK := object["allowed"].(bool)
	approval, pOK := object["requires_approval"].(bool)
	deny, dOK := ruleIDs(object["deny"], "FORGE-PLAN-INVALID FORGE-001 FORGE-002 FORGE-003 FORGE-004 FORGE-005 FORGE-006 FORGE-007")
	warn, wOK := ruleIDs(object["warn"], "FORGE-010")
	approve, rOK := ruleIDs(object["approval"], "FORGE-008 FORGE-009")
	if !aOK || !pOK || !dOK || !wOK || !rOK || allowed != (len(deny) == 0) || approval != (len(approve) > 0) {
		return Decision{}, ErrEvaluation
	}
	return Decision{Deny: deny, Warn: warn, Approval: approve, Allowed: allowed, RequiresApproval: approval}, nil
}

func ruleIDs(value any, permitted string) ([]string, bool) {
	values, ok := value.([]any)
	if !ok || len(values) > 8 {
		return nil, false
	}
	ids := make([]string, 0, len(values))
	for _, value := range values {
		id, ok := value.(string)
		if !ok || !slices.Contains(strings.Fields(permitted), id) || (len(ids) > 0 && ids[len(ids)-1] >= id) {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}
