package engine

import (
	"context"
	"strings"
	"testing"

	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

// newErrorTestEngine builds a zanzibar engine with the minimal model and
// one seed tuple (user:alice viewer document:test-doc), then loads the
// given rego source as a bundle.
func newErrorTestEngine(t *testing.T, regoSrc string) (*Engine, context.Context) {
	t.Helper()
	const tid = "tenant-error-test"
	ctx := store.ContextWithTenant(context.Background(), tid)

	ms := store.NewMemoryStore()
	zEngine := zanzibar.New(ms, nil, nil)
	if err := zEngine.LoadModelForTenant(ctx, tid, minimalModelYAML); err != nil {
		t.Fatalf("load model: %v", err)
	}
	if err := zEngine.WriteTuple(ctx, "user:alice", "viewer", "document:test-doc"); err != nil {
		t.Fatalf("write seed tuple: %v", err)
	}

	e := New(zEngine)
	packed, err := packRegoBundle([]byte(regoSrc))
	if err != nil {
		t.Fatalf("pack bundle: %v", err)
	}
	if err := e.LoadBundle(packed, nil); err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return e, ctx
}

var errorTestInput = EvalInput{
	User:         "user:alice",
	Relation:     "viewer",
	Object:       "document:test-doc",
	ResourceType: "document",
	ResourceID:   "test-doc",
}

// TestEvaluate_EvalErrorSurfaced pins BLOCKER semantics: an OPA evaluation
// ERROR (here, a complete-rule conflict) must be returned to the caller --
// never silently degraded into a bare Zanzibar fallback that would have
// allowed the request.
func TestEvaluate_EvalErrorSurfaced(t *testing.T) {
	// Two complete rules assign conflicting values for the same input --
	// guaranteed eval_conflict_error at evaluation time.
	e, ctx := newErrorTestEngine(t, `package atol
import rego.v1
allow := true if { input.relation == "viewer" }
allow := false if { input.relation == "viewer" }
`)

	result, err := e.Evaluate(ctx, errorTestInput)
	if err == nil {
		t.Fatalf("Evaluate with conflicting rules: err = nil, want eval error (result=%+v)", result)
	}
	if result != nil {
		t.Errorf("Evaluate returned non-nil result alongside error: %+v", result)
	}
	if !strings.Contains(err.Error(), "opa eval") {
		t.Errorf("error %q does not identify the failing query path", err)
	}
}

// TestEvaluate_UndefinedFallsBackToZanzibar pins the designed fallback: a
// bundle that has no opinion (every query path undefined) falls back to a
// bare Zanzibar check rather than denying.
func TestEvaluate_UndefinedFallsBackToZanzibar(t *testing.T) {
	// No default and a guard that never fires for our input: the allow
	// rule is undefined on all query paths.
	e, ctx := newErrorTestEngine(t, `package atol
import rego.v1
allow := true if { input.relation == "relation-that-never-matches" }
`)

	result, err := e.Evaluate(ctx, errorTestInput)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed {
		t.Errorf("fallback check: allowed = false, want true (tuple exists). trace=%v", result.Trace)
	}
	if result.MatchedRule != "zanzibar.check" {
		t.Errorf("MatchedRule = %q, want zanzibar.check (fallback)", result.MatchedRule)
	}
}

// TestEvaluate_MatchedRuleIsActualQueryPath pins that the engine reports
// the real matched query path -- not a hardcoded value -- so decision logs
// show which rule produced the decision.
func TestEvaluate_MatchedRuleIsActualQueryPath(t *testing.T) {
	e, ctx := newErrorTestEngine(t, `package atol
import rego.v1
default allow := false
allow if zanzibar.check(input.user, input.relation, input.object)
`)

	result, err := e.Evaluate(ctx, errorTestInput)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("allowed = false, want true. trace=%v", result.Trace)
	}
	// The resource-type-specific path has no rules, so the generic
	// boolean path is the one that matched.
	if result.MatchedRule != "data.atol.allow" {
		t.Errorf("MatchedRule = %q, want data.atol.allow", result.MatchedRule)
	}
}
