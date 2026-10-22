package zanzibar

import (
	"context"
	"errors"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

type testServingGate struct {
	err     error
	tenants []string
}

func (g *testServingGate) RequireActive(tenantID string) error {
	g.tenants = append(g.tenants, tenantID)
	return g.err
}

func TestAuthorizationEntryPointsFailClosedAtServingGate(t *testing.T) {
	t.Parallel()
	denied := errors.New("tenant lease expired")
	gate := &testServingGate{err: denied}
	engine := New(store.NewMemoryStore(), nil, nil)
	engine.SetTenantServingGate(gate)
	ctx := store.ContextWithTenant(context.Background(), "tenant-a")

	if allowed, err := engine.Check(ctx, "user:alice", "viewer", "document:a"); allowed || !errors.Is(err, denied) {
		t.Fatalf("Check() = (%v, %v), want denied", allowed, err)
	}
	if allowed, err := engine.CheckWithContextTuples(ctx, "user:alice", "viewer", "document:a", nil); allowed || !errors.Is(err, denied) {
		t.Fatalf("CheckWithContextTuples() = (%v, %v), want denied", allowed, err)
	}
	if allowed, _, err := engine.CheckDebug(ctx, "user:alice", "viewer", "document:a"); allowed || !errors.Is(err, denied) {
		t.Fatalf("CheckDebug() = (%v, %v), want denied", allowed, err)
	}
	if objects, err := engine.ListObjects(ctx, "user:alice", "viewer", "document"); objects != nil || !errors.Is(err, denied) {
		t.Fatalf("ListObjects() = (%v, %v), want denied", objects, err)
	}
	if users, err := engine.ListUsers(ctx, "viewer", "document:a"); users != nil || !errors.Is(err, denied) {
		t.Fatalf("ListUsers() = (%v, %v), want denied", users, err)
	}
	if len(gate.tenants) != 5 {
		t.Fatalf("gate calls = %d, want 5", len(gate.tenants))
	}
	for _, tenantID := range gate.tenants {
		if tenantID != "tenant-a" {
			t.Fatalf("gate tenant = %q, want tenant-a", tenantID)
		}
	}
}

func TestReadTuplePageDoesNotFallbackToUnboundedRead(t *testing.T) {
	t.Parallel()
	engine := New(&plainStore{inner: store.NewMemoryStore()}, nil, nil)
	_, _, err := engine.ReadTuplePage(context.Background(), model.TupleFilter{}, "", 1)
	if !errors.Is(err, store.ErrTuplePageUnsupported) {
		t.Fatalf("ReadTuplePage() error = %v, want ErrTuplePageUnsupported", err)
	}
}
