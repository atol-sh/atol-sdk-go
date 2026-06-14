package engine

import (
	"context"
	"testing"

	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

// benchEngine builds an engine with the minimal model, one tuple, and an
// optional bundle. Mirrors the production hot path: bundle loaded once,
// Evaluate called per request.
func benchEngine(b *testing.B, regoSrc string) (*Engine, context.Context) {
	b.Helper()
	const tid = "tenant-bench"
	ctx := store.ContextWithTenant(context.Background(), tid)

	ms := store.NewMemoryStore()
	zEngine := zanzibar.New(ms, nil, nil)
	if err := zEngine.LoadModelForTenant(ctx, tid, minimalModelYAML); err != nil {
		b.Fatalf("load model: %v", err)
	}
	if err := zEngine.WriteTuple(ctx, "user:alice", "viewer", "document:test-doc"); err != nil {
		b.Fatalf("write tuple: %v", err)
	}

	e := New(zEngine)
	if regoSrc != "" {
		packed, err := packRegoBundle([]byte(regoSrc))
		if err != nil {
			b.Fatalf("pack bundle: %v", err)
		}
		if err := e.LoadBundle(packed, nil); err != nil {
			b.Fatalf("load bundle: %v", err)
		}
	}
	return e, ctx
}

var benchInput = EvalInput{
	User:         "user:alice",
	Relation:     "viewer",
	Object:       "document:test-doc",
	ResourceType: "document",
	ResourceID:   "test-doc",
}

// BenchmarkEvaluate_WithBundle measures the full OPA-evaluation hot path
// with a loaded bundle and a zanzibar.check() built-in call -- the path
// behind Authorize/Can/Check in production. This is the path the <250us
// claim must hold for, served by PreparedEvalQuery.
func BenchmarkEvaluate_WithBundle(b *testing.B) {
	e, ctx := benchEngine(b, `package atol
import rego.v1
default allow := false
allow if zanzibar.check(input.user, input.relation, input.object)
`)

	// Warm the prepared-query cache the way the first request would.
	if r, err := e.Evaluate(ctx, benchInput); err != nil || !r.Allowed {
		b.Fatalf("warmup evaluate: allowed=%v err=%v", r != nil && r.Allowed, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := e.Evaluate(ctx, benchInput)
		if err != nil {
			b.Fatalf("evaluate: %v", err)
		}
		if !r.Allowed {
			b.Fatal("evaluate: allowed=false, want true")
		}
	}
}

// BenchmarkEvaluate_FallbackZanzibar measures the bare-Zanzibar fallback
// path (no bundle loaded) for comparison against the OPA path.
func BenchmarkEvaluate_FallbackZanzibar(b *testing.B) {
	e, ctx := benchEngine(b, "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := e.Evaluate(ctx, benchInput)
		if err != nil {
			b.Fatalf("evaluate: %v", err)
		}
		if !r.Allowed {
			b.Fatal("evaluate: allowed=false, want true")
		}
	}
}
