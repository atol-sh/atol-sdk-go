package engine

import (
	"context"
	"sync"
	"testing"

	"atol.sh/sdk-go/policy"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// TestZanzibarCheckBuiltin_PreservesTenantContext asserts tenant
// isolation through the OPA → zanzibar.check → tuple-store pipeline.
// Mirrors the control-plane test at
// internal/opa/engine_test.go::TestBuiltinWithTenantScopedStore so the
// two OPA builtins evolve together.
//
// Empirical note: current OPA v1 propagates ctx.Value through
// rego.BuiltinContext.Context, so under today's upstream this test
// would pass with or without the evalCtx shortcut. We keep the
// shortcut (see builtins.go) as defense-in-depth -- the control plane
// adopted the same pattern, and if a future OPA version stops
// propagating values (partial eval, new scheduler, etc.) both code
// paths continue to work. See project_opa_zanzibar_bug.md memory note.
func TestZanzibarCheckBuiltin_PreservesTenantContext(t *testing.T) {
	const tenantID = "tenant-a"
	ctx := store.ContextWithTenant(context.Background(), tenantID)

	tsStore := newTenantScopedStore()
	zEngine := zanzibar.New(tsStore, nil, nil)
	if err := zEngine.LoadModelForTenant(ctx, tenantID, minimalModelYAML); err != nil {
		t.Fatalf("load model: %v", err)
	}
	if err := zEngine.WriteTuple(ctx, "user:alice", "viewer", "document:test-doc"); err != nil {
		t.Fatalf("write tuple: %v", err)
	}

	// Sanity: direct check WITH tenant ctx passes, WITHOUT fails.
	if allowed, err := zEngine.Check(ctx, "user:alice", "viewer", "document:test-doc"); err != nil || !allowed {
		t.Fatalf("direct check with tenant: allowed=%v, err=%v", allowed, err)
	}
	if allowed, _ := zEngine.Check(context.Background(), "user:alice", "viewer", "document:test-doc"); allowed {
		t.Fatal("direct check without tenant must return false")
	}

	m := zEngine.GetModelForTenant(ctx, tenantID)
	bundleData, err := policy.GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("generate default policy: %v", err)
	}

	opaEngine := New(zEngine)
	if err := opaEngine.LoadBundle(bundleData, nil); err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	// The OPA eval must preserve the tenant in ctx through into the
	// zanzibar.check built-in's store read.
	result, err := opaEngine.Evaluate(ctx, EvalInput{
		User:         "user:alice",
		Relation:     "viewer",
		Object:       "document:test-doc",
		ResourceType: "document",
		ResourceID:   "test-doc",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.Allowed {
		t.Errorf("tenant-scoped evaluate: allowed=false, want true. trace=%v", result.Trace)
	}
}

// TestZanzibarCheckBuiltin_IsolatesTenants confirms that two tenants
// holding the same (user, relation, object) with different truth values
// -- tenant A grants, tenant B does not -- produce independent decisions.
// This guards the cross-tenant isolation invariant at the OPA + ReBAC
// integration boundary.
func TestZanzibarCheckBuiltin_IsolatesTenants(t *testing.T) {
	const (
		tenantA = "tenant-alpha"
		tenantB = "tenant-beta"
	)
	ctxA := store.ContextWithTenant(context.Background(), tenantA)
	ctxB := store.ContextWithTenant(context.Background(), tenantB)

	tsStore := newTenantScopedStore()
	zEngine := zanzibar.New(tsStore, nil, nil)

	for _, tid := range []string{tenantA, tenantB} {
		if err := zEngine.LoadModelForTenant(
			store.ContextWithTenant(context.Background(), tid),
			tid, minimalModelYAML,
		); err != nil {
			t.Fatalf("load model %s: %v", tid, err)
		}
	}
	// Only tenant A grants access.
	if err := zEngine.WriteTuple(ctxA, "user:carol", "viewer", "document:report"); err != nil {
		t.Fatalf("write tuple A: %v", err)
	}

	bundleData, err := policy.GenerateDefaultPolicy(zEngine.GetModelForTenant(ctxA, tenantA))
	if err != nil {
		t.Fatalf("generate default policy: %v", err)
	}
	opaEngine := New(zEngine)
	if err := opaEngine.LoadBundle(bundleData, nil); err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	input := EvalInput{
		User:         "user:carol",
		Relation:     "viewer",
		Object:       "document:report",
		ResourceType: "document",
		ResourceID:   "report",
	}

	rA, err := opaEngine.Evaluate(ctxA, input)
	if err != nil {
		t.Fatalf("evaluate A: %v", err)
	}
	if !rA.Allowed {
		t.Errorf("tenant A: allowed=false, want true. trace=%v", rA.Trace)
	}

	rB, err := opaEngine.Evaluate(ctxB, input)
	if err != nil {
		t.Fatalf("evaluate B: %v", err)
	}
	if rB.Allowed {
		t.Errorf("tenant B: allowed=true, want false (no tuple in B's partition). trace=%v", rB.Trace)
	}
}

// minimalModelYAML is the smallest model that exercises a `viewer`
// relation on a `document` type -- enough for the zanzibar.check
// built-in to compile a real rule path in the auto-generated bundle.
var minimalModelYAML = []byte(`version: "1.0"
types:
  user: {}
  document:
    relations:
      viewer:
        types: [user]
`)

// tenantScopedStore mirrors the helper in
// atol/internal/opa/engine_test.go. It wraps a per-tenant MemoryStore
// and resolves the inner store by reading the tenant key from ctx,
// the same way the production PostgresStore does.
type tenantScopedStore struct {
	mu     sync.RWMutex
	stores map[string]*store.MemoryStore
}

func newTenantScopedStore() *tenantScopedStore {
	return &tenantScopedStore{stores: make(map[string]*store.MemoryStore)}
}

func (s *tenantScopedStore) resolve(ctx context.Context) *store.MemoryStore {
	tid := store.TenantFromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.stores[tid]; !ok {
		s.stores[tid] = store.NewMemoryStore()
	}
	return s.stores[tid]
}

func (s *tenantScopedStore) Write(ctx context.Context, t model.Tuple) error {
	return s.resolve(ctx).Write(ctx, t)
}

func (s *tenantScopedStore) Delete(ctx context.Context, t model.Tuple) error {
	return s.resolve(ctx).Delete(ctx, t)
}

func (s *tenantScopedStore) Read(ctx context.Context, filter model.TupleFilter) ([]model.Tuple, error) {
	return s.resolve(ctx).Read(ctx, filter)
}

func (s *tenantScopedStore) ReadUsersets(ctx context.Context, objectType, objectID, relation string) ([]model.Tuple, error) {
	return s.resolve(ctx).ReadUsersets(ctx, objectType, objectID, relation)
}
