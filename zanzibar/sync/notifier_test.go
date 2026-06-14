package sync

import (
	"context"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
)

// The sync package currently exposes just a ChangeNotifier interface
// and a NoopNotifier. Tests here pin the contract: NoopNotifier
// satisfies the interface, never panics, and is safe to call with
// zero-value inputs. A richer state machine (e.g., bounded in-memory
// queue, backpressure) would land its own tests alongside the
// implementation when added.

// TestNoopNotifier_ImplementsInterface is a compile-time guard --
// the var assignment fails to compile if NoopNotifier drifts away
// from the interface contract.
func TestNoopNotifier_ImplementsInterface(t *testing.T) {
	var _ ChangeNotifier = NoopNotifier{}
}

// TestNoopNotifier_NeverPanics exercises every method with realistic
// and degenerate inputs.
func TestNoopNotifier_NeverPanics(t *testing.T) {
	var n ChangeNotifier = NoopNotifier{}
	ctx := context.Background()

	// Zero value.
	n.OnTupleWrite(ctx, model.Tuple{})
	n.OnTupleDelete(ctx, model.Tuple{})
	n.OnModelUpdate(ctx, "", nil)

	// Realistic tuple.
	tup := model.Tuple{
		ObjectType: "doc", ObjectID: "42", Relation: "viewer",
		UserType: "user", UserID: "alice",
	}
	n.OnTupleWrite(ctx, tup)
	n.OnTupleDelete(ctx, tup)

	// Non-nil model.
	m := &model.Model{Version: "1.0", Types: map[string]*model.TypeDef{}}
	n.OnModelUpdate(ctx, "tenant", m)
}

// spyNotifier records every callback for assertions, standing in for a
// real implementation under future tests. Verifies the interface can
// be cleanly mocked.
type spyNotifier struct {
	writes  []model.Tuple
	deletes []model.Tuple
	models  map[string]*model.Model
}

func (s *spyNotifier) OnTupleWrite(_ context.Context, t model.Tuple) { s.writes = append(s.writes, t) }
func (s *spyNotifier) OnTupleDelete(_ context.Context, t model.Tuple) {
	s.deletes = append(s.deletes, t)
}
func (s *spyNotifier) OnModelUpdate(_ context.Context, tenantID string, m *model.Model) {
	if s.models == nil {
		s.models = make(map[string]*model.Model)
	}
	s.models[tenantID] = m
}

// TestSpyNotifier_RecordsEverything demonstrates a fake implementation
// and gives future callers (e.g., the control plane's reactor) a
// pattern to copy.
func TestSpyNotifier_RecordsEverything(t *testing.T) {
	spy := &spyNotifier{}
	var n ChangeNotifier = spy
	ctx := context.Background()

	n.OnTupleWrite(ctx, model.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "viewer"})
	n.OnTupleDelete(ctx, model.Tuple{ObjectType: "doc", ObjectID: "2", Relation: "viewer"})
	n.OnModelUpdate(ctx, "tenant-A", &model.Model{Version: "1.0"})
	n.OnModelUpdate(ctx, "tenant-B", &model.Model{Version: "1.0"})

	if len(spy.writes) != 1 || spy.writes[0].ObjectID != "1" {
		t.Errorf("writes = %v", spy.writes)
	}
	if len(spy.deletes) != 1 || spy.deletes[0].ObjectID != "2" {
		t.Errorf("deletes = %v", spy.deletes)
	}
	if len(spy.models) != 2 {
		t.Errorf("models = %v, want 2 entries", spy.models)
	}
}
