package zanzibar

import (
	"context"
	"errors"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// guardedModelYAML is a minimal model with one `required` relation (org.owner)
// plus an unguarded relation (org.member) and a userset-capable relation.
const guardedModelYAML = `
version: "1.0"
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
  team:
    relations:
      member:
        types: [user]
  org:
    relations:
      owner:
        types: [user, team#member]
        required: true
      member:
        types: [user]
`

func newGuardedEngine(t *testing.T) (*Engine, *spyNotifier) {
	t.Helper()
	spy := &spyNotifier{}
	e := New(store.NewMemoryStore(), nil, spy)
	if err := e.LoadModel([]byte(guardedModelYAML)); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	return e, spy
}

// spyNotifier records every fan-out call so tests can assert exact emit counts.
type spyNotifier struct {
	writes  []model.Tuple
	deletes []model.Tuple
}

func (s *spyNotifier) OnTupleWrite(_ context.Context, t model.Tuple) { s.writes = append(s.writes, t) }
func (s *spyNotifier) OnTupleDelete(_ context.Context, t model.Tuple) {
	s.deletes = append(s.deletes, t)
}
func (s *spyNotifier) OnModelUpdate(_ context.Context, _ string, _ *model.Model) {}

// plainStore wraps a TupleStore so it implements ONLY the base interface,
// hiding MemoryStore's ConditionalDeleter / TupleTxStore capabilities.
type plainStore struct {
	inner store.TupleStore
}

func (p *plainStore) Write(ctx context.Context, t model.Tuple) error { return p.inner.Write(ctx, t) }
func (p *plainStore) Delete(ctx context.Context, t model.Tuple) error {
	return p.inner.Delete(ctx, t)
}
func (p *plainStore) Read(ctx context.Context, f model.TupleFilter) ([]model.Tuple, error) {
	return p.inner.Read(ctx, f)
}
func (p *plainStore) ReadUsersets(ctx context.Context, ot, oid, rel string) ([]model.Tuple, error) {
	return p.inner.ReadUsersets(ctx, ot, oid, rel)
}

func ownerCount(t *testing.T, e *Engine) int {
	t.Helper()
	got, err := e.ReadTuples(context.Background(), model.TupleFilter{
		ObjectType: "org", ObjectID: "acme", Relation: "owner",
	})
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	return len(got)
}

func TestDeleteTuple_RequiredGuard(t *testing.T) {
	ctx := context.Background()

	t.Run("two holders, delete one is allowed", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.WriteTuple(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple alice: %v", err)
		}
		if err := e.WriteTuple(ctx, "user:bob", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple bob: %v", err)
		}
		if err := e.DeleteTuple(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Fatalf("DeleteTuple(non-last) error = %v, want nil", err)
		}
		if got := ownerCount(t, e); got != 1 {
			t.Errorf("owner count after delete = %d, want 1", got)
		}
	})

	t.Run("delete last holder is refused and tuple preserved", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.WriteTuple(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple alice: %v", err)
		}
		err := e.DeleteTuple(ctx, "user:alice", "owner", "org:acme")
		if !errors.Is(err, model.ErrLastHolder) {
			t.Fatalf("DeleteTuple(last) error = %v, want ErrLastHolder", err)
		}
		if got := ownerCount(t, e); got != 1 {
			t.Errorf("owner count after refused delete = %d, want 1 (preserved)", got)
		}
	})

	t.Run("userset tuple on guarded relation is not blocked", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		// A single userset holder (team:eng#member) on the guarded relation.
		if err := e.WriteTuple(ctx, "team:eng#member", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple userset: %v", err)
		}
		// Deleting the userset must not be blocked even though it is the only
		// holder: the floor counts direct holders only.
		if err := e.DeleteTuple(ctx, "team:eng#member", "owner", "org:acme"); err != nil {
			t.Fatalf("DeleteTuple(userset) error = %v, want nil", err)
		}
		if got := ownerCount(t, e); got != 0 {
			t.Errorf("owner count after userset delete = %d, want 0", got)
		}
	})

	t.Run("delete of non-existent tuple on guarded relation returns nil", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.DeleteTuple(ctx, "user:ghost", "owner", "org:acme"); err != nil {
			t.Fatalf("DeleteTuple(missing) error = %v, want nil", err)
		}
	})

	t.Run("unguarded relation deletes freely", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.WriteTuple(ctx, "user:alice", "member", "org:acme"); err != nil {
			t.Fatalf("WriteTuple member: %v", err)
		}
		if err := e.DeleteTuple(ctx, "user:alice", "member", "org:acme"); err != nil {
			t.Fatalf("DeleteTuple(unguarded last) error = %v, want nil", err)
		}
	})

	t.Run("store without ConditionalDeleter fails loud", func(t *testing.T) {
		spy := &spyNotifier{}
		e := New(&plainStore{inner: store.NewMemoryStore()}, nil, spy)
		if err := e.LoadModel([]byte(guardedModelYAML)); err != nil {
			t.Fatalf("LoadModel: %v", err)
		}
		// Seed two holders via the base Write so the floor is not the issue.
		if err := e.WriteTuple(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple alice: %v", err)
		}
		if err := e.WriteTuple(ctx, "user:bob", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple bob: %v", err)
		}
		err := e.DeleteTuple(ctx, "user:alice", "owner", "org:acme")
		if err == nil {
			t.Fatal("DeleteTuple on store without ConditionalDeleter = nil, want fail-loud error")
		}
		if errors.Is(err, model.ErrLastHolder) {
			t.Errorf("error = %v, want a capability error, not ErrLastHolder", err)
		}
	})
}

func TestCanDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("last holder returns ErrLastHolder without mutating", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.WriteTuple(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple: %v", err)
		}
		err := e.CanDelete(ctx, "user:alice", "owner", "org:acme")
		if !errors.Is(err, model.ErrLastHolder) {
			t.Fatalf("CanDelete(last) = %v, want ErrLastHolder", err)
		}
		// CanDelete must not have mutated the store.
		if got := ownerCount(t, e); got != 1 {
			t.Errorf("owner count after CanDelete = %d, want 1 (read-only)", got)
		}
	})

	t.Run("non-last holder returns nil", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.WriteTuple(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple alice: %v", err)
		}
		if err := e.WriteTuple(ctx, "user:bob", "owner", "org:acme"); err != nil {
			t.Fatalf("WriteTuple bob: %v", err)
		}
		if err := e.CanDelete(ctx, "user:alice", "owner", "org:acme"); err != nil {
			t.Errorf("CanDelete(non-last) = %v, want nil", err)
		}
	})

	t.Run("unguarded relation returns nil", func(t *testing.T) {
		e, _ := newGuardedEngine(t)
		if err := e.WriteTuple(ctx, "user:alice", "member", "org:acme"); err != nil {
			t.Fatalf("WriteTuple: %v", err)
		}
		if err := e.CanDelete(ctx, "user:alice", "member", "org:acme"); err != nil {
			t.Errorf("CanDelete(unguarded) = %v, want nil", err)
		}
	})
}

func TestWriteRelationships(t *testing.T) {
	ctx := context.Background()

	t.Run("empty batch is a no-op", func(t *testing.T) {
		e, spy := newGuardedEngine(t)
		if err := e.WriteRelationships(ctx, nil, nil); err != nil {
			t.Fatalf("WriteRelationships(empty) = %v, want nil", err)
		}
		if len(spy.writes) != 0 || len(spy.deletes) != 0 {
			t.Errorf("empty batch emitted writes=%d deletes=%d, want 0/0", len(spy.writes), len(spy.deletes))
		}
	})

	t.Run("3 writes + 2 deletes apply all-or-nothing", func(t *testing.T) {
		e, spy := newGuardedEngine(t)
		// Seed two member tuples to be deleted.
		seed := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "old1"},
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "old2"},
		}
		if err := e.WriteRelationships(ctx, seed, nil); err != nil {
			t.Fatalf("seed WriteRelationships: %v", err)
		}
		spy.writes = nil
		spy.deletes = nil

		writes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "new1"},
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "new2"},
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "new3"},
		}
		deletes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "old1"},
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "old2"},
		}
		if err := e.WriteRelationships(ctx, writes, deletes); err != nil {
			t.Fatalf("WriteRelationships: %v", err)
		}

		got, _ := e.ReadTuples(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member"})
		if len(got) != 3 {
			t.Errorf("member count = %d, want 3", len(got))
		}
		if len(spy.writes) != 3 {
			t.Errorf("OnTupleWrite fired %d times, want 3", len(spy.writes))
		}
		if len(spy.deletes) != 2 {
			t.Errorf("OnTupleDelete fired %d times, want 2", len(spy.deletes))
		}
	})

	t.Run("mid-batch store error leaves nothing applied and emits nothing", func(t *testing.T) {
		spy := &spyNotifier{}
		failAt := errors.New("injected tx failure")
		fs := &failingTxStore{TupleStore: store.NewMemoryStore(), err: failAt}
		e := New(fs, nil, spy)
		if err := e.LoadModel([]byte(guardedModelYAML)); err != nil {
			t.Fatalf("LoadModel: %v", err)
		}
		writes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "a"},
		}
		err := e.WriteRelationships(ctx, writes, nil)
		if !errors.Is(err, failAt) {
			t.Fatalf("WriteRelationships error = %v, want injected failure", err)
		}
		got, _ := e.ReadTuples(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member"})
		if len(got) != 0 {
			t.Errorf("store applied %d tuples on failed tx, want 0", len(got))
		}
		if len(spy.writes) != 0 || len(spy.deletes) != 0 {
			t.Errorf("notifier fired on failed tx: writes=%d deletes=%d, want 0/0", len(spy.writes), len(spy.deletes))
		}
	})

	t.Run("invalid write is rejected before any store call", func(t *testing.T) {
		spy := &spyNotifier{}
		cs := &countingTxStore{TupleStore: store.NewMemoryStore()}
		e := New(cs, nil, spy)
		if err := e.LoadModel([]byte(guardedModelYAML)); err != nil {
			t.Fatalf("LoadModel: %v", err)
		}
		// "phantom" relation does not exist on org -> ValidateTuple fails.
		writes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "ok"},
			{ObjectType: "org", ObjectID: "acme", Relation: "phantom", UserType: "user", UserID: "bad"},
		}
		err := e.WriteRelationships(ctx, writes, nil)
		if err == nil {
			t.Fatal("WriteRelationships(invalid write) = nil, want validation error")
		}
		if cs.txCalls != 0 {
			t.Errorf("WriteTx called %d times on invalid batch, want 0", cs.txCalls)
		}
		if len(spy.writes) != 0 {
			t.Errorf("notifier fired %d writes on invalid batch, want 0", len(spy.writes))
		}
	})

	t.Run("store without TupleTxStore returns ErrNotTransactional", func(t *testing.T) {
		spy := &spyNotifier{}
		e := New(&plainStore{inner: store.NewMemoryStore()}, nil, spy)
		if err := e.LoadModel([]byte(guardedModelYAML)); err != nil {
			t.Fatalf("LoadModel: %v", err)
		}
		writes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "a"},
		}
		err := e.WriteRelationships(ctx, writes, nil)
		if !errors.Is(err, ErrNotTransactional) {
			t.Fatalf("WriteRelationships = %v, want ErrNotTransactional", err)
		}
		if len(spy.writes) != 0 {
			t.Errorf("notifier fired on non-transactional store, want 0")
		}
	})
}

// failingTxStore implements TupleTxStore but always fails WriteTx.
type failingTxStore struct {
	store.TupleStore
	err error
}

func (f *failingTxStore) WriteTx(_ context.Context, _, _ []model.Tuple) error { return f.err }

// countingTxStore implements TupleTxStore and records how many times WriteTx
// was called, delegating to an inner MemoryStore on success.
type countingTxStore struct {
	store.TupleStore
	txCalls int
}

func (c *countingTxStore) WriteTx(ctx context.Context, writes, deletes []model.Tuple) error {
	c.txCalls++
	tx, ok := c.TupleStore.(store.TupleTxStore)
	if !ok {
		return ErrNotTransactional
	}
	return tx.WriteTx(ctx, writes, deletes)
}
