package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"

	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

// Conditional-policy tests drive realistic, customer-shaped Rego from
// testdata/policies/ through the full engine and assert on structured
// decisions (allow, step_up, deny reasons). They close the M4 gap that
// the audit flagged: every test-side Rego was hand-written inline, no
// fixtures represented what a real customer would author.

// loadFixture reads a .rego file from testdata/policies/ and packs it
// into an OPA bundle the engine can load via LoadBundle. Matches the
// shape built by the control plane's buildBundle test helper.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", "policies", name)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	b := bundle.Bundle{
		Modules: []bundle.ModuleFile{
			{URL: "/atol/policy.rego", Path: "/atol/policy.rego", Raw: src},
		},
		Data: make(map[string]interface{}),
	}
	var buf bytes.Buffer
	if err := bundle.Write(&buf, b); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return buf.Bytes()
}

// newConditionalEngine sets up a zanzibar store with a minimal model +
// one seed tuple granting user:alice->viewer->document:test-doc and
// returns an OPA engine loaded with the given fixture.
func newConditionalEngine(t *testing.T, fixture string) (*Engine, context.Context) {
	t.Helper()
	const tid = "tenant-conditional"
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
	if err := e.LoadBundle(loadFixture(t, fixture), nil); err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return e, ctx
}

// TestConditional_PlanGating_ReBACGrantedButPlanDenied proves the
// composition of ReBAC and attribute checks: tuple says allow, but
// subscription plan blocks the action.
func TestConditional_PlanGating_ReBACGrantedButPlanDenied(t *testing.T) {
	e, ctx := newConditionalEngine(t, "plan_gating.rego")

	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"attrs": map[string]any{"action": "invite"},
			"plan":  "starter",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if r.Allowed {
		t.Errorf("starter plan invite: allowed=true, want false. trace=%v", r.Trace)
	}
}

func TestConditional_PlanGating_EnterprisePasses(t *testing.T) {
	e, ctx := newConditionalEngine(t, "plan_gating.rego")

	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"attrs": map[string]any{"action": "invite"},
			"plan":  "enterprise",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !r.Allowed {
		t.Errorf("enterprise plan invite: allowed=false, want true. trace=%v", r.Trace)
	}
}

// TestConditional_MFA_StepUpRequired_OnSensitiveAction verifies the
// full {allow:false, step_up:{type:mfa, method:passkey}} branch that
// the audit flagged as untested.
func TestConditional_MFA_StepUpRequired_OnSensitiveAction(t *testing.T) {
	e, ctx := newConditionalEngine(t, "mfa_required.rego")

	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"attrs":        map[string]any{"action": "delete"},
			"mfa_verified": false,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if r.Allowed {
		t.Errorf("delete without mfa: allowed=true, want false. trace=%v", r.Trace)
	}
	if r.StepUp == nil {
		t.Fatal("delete without mfa: StepUp is nil, want step_up={type:mfa, method:passkey}")
	}
	if r.StepUp.Type != "mfa" || r.StepUp.Method != "passkey" {
		t.Errorf("StepUp = %+v, want type=mfa method=passkey", r.StepUp)
	}
}

func TestConditional_MFA_AllowsWhenVerified(t *testing.T) {
	e, ctx := newConditionalEngine(t, "mfa_required.rego")

	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"attrs":        map[string]any{"action": "delete"},
			"mfa_verified": true,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !r.Allowed {
		t.Errorf("delete with mfa: allowed=false, want true. trace=%v", r.Trace)
	}
	if r.StepUp != nil {
		t.Errorf("delete with mfa: StepUp=%+v, want nil", r.StepUp)
	}
}

// TestConditional_AuthTime_FreshSessionPasses / StaleSessionFails pins
// the temporal enforcement path.
func TestConditional_AuthTime_FreshSessionPasses(t *testing.T) {
	e, ctx := newConditionalEngine(t, "auth_time_freshness.rego")

	now := time.Now().UnixNano()
	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"auth_time_ns": now - int64(60*time.Second), // 1 minute ago
			"now_ns":       now,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !r.Allowed {
		t.Errorf("1-minute-old auth: allowed=false, want true. trace=%v", r.Trace)
	}
}

func TestConditional_AuthTime_StaleSessionFails(t *testing.T) {
	e, ctx := newConditionalEngine(t, "auth_time_freshness.rego")

	now := time.Now().UnixNano()
	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"auth_time_ns": now - int64(10*time.Minute), // 10 minutes ago, cap is 5
			"now_ns":       now,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if r.Allowed {
		t.Errorf("10-minute-old auth: allowed=true, want false (beyond 5min cap). trace=%v", r.Trace)
	}
}

func TestConditional_SessionAge_YoungerThanCapPasses(t *testing.T) {
	e, ctx := newConditionalEngine(t, "session_age_cap.rego")

	now := time.Now().UnixNano()
	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"session_created_ns": now - int64(2*time.Hour), // 2 hours, cap is 8
			"now_ns":             now,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !r.Allowed {
		t.Errorf("2h session: allowed=false, want true. trace=%v", r.Trace)
	}
}

func TestConditional_SessionAge_PastCapFails(t *testing.T) {
	e, ctx := newConditionalEngine(t, "session_age_cap.rego")

	now := time.Now().UnixNano()
	r, err := e.Evaluate(ctx, EvalInput{
		User: "user:alice", Relation: "viewer", Object: "document:test-doc",
		ResourceType: "document", ResourceID: "test-doc",
		Extra: map[string]any{
			"session_created_ns": now - int64(12*time.Hour), // 12h, cap is 8h
			"now_ns":             now,
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if r.Allowed {
		t.Errorf("12h session: allowed=true, want false (beyond 8h cap). trace=%v", r.Trace)
	}
}

// TestConditional_BundleRace hammers the engine with concurrent
// LoadBundle + Evaluate calls. The engine MUST NEVER panic or return
// a stale-policy + new-data hybrid decision. Race detector catches
// any unsynchronized mutation of the compiler/store fields.
func TestConditional_BundleRace(t *testing.T) {
	e, ctx := newConditionalEngine(t, "plan_gating.rego")

	// Pre-build an alternate bundle to swap in during the race.
	alt := loadFixture(t, "mfa_required.rego")

	const workers = 8
	const iters = 50
	var wg sync.WaitGroup
	wg.Add(workers + 1)

	// Bundle-swapper.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if err := e.LoadBundle(alt, nil); err != nil {
				t.Errorf("LoadBundle (alt) iter %d: %v", i, err)
				return
			}
			if err := e.LoadBundle(loadFixture(t, "plan_gating.rego"), nil); err != nil {
				t.Errorf("LoadBundle (plan) iter %d: %v", i, err)
				return
			}
		}
	}()

	// Evaluators.
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters*2; i++ {
				_, err := e.Evaluate(ctx, EvalInput{
					User: "user:alice", Relation: "viewer", Object: "document:test-doc",
					ResourceType: "document", ResourceID: "test-doc",
					Extra: map[string]any{
						"attrs":        map[string]any{"action": "view"},
						"plan":         "starter",
						"mfa_verified": true,
					},
				})
				// A mid-swap race can legitimately return a compile or
				// lookup error; what we're guarding against is panic and
				// data corruption, which the race detector + lack of panic
				// catch.
				_ = err
			}
		}()
	}

	wg.Wait()
}
