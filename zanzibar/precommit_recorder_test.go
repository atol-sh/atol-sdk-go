package zanzibar

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

var errPrecommitRecorder = errors.New("precommit recorder failed")

type trackingTupleStore struct {
	inner              *store.MemoryStore
	order              *[]string
	writes             int
	deletes            int
	conditionalDeletes int
	transactions       int
}

func newTrackingTupleStore(order *[]string) *trackingTupleStore {
	return &trackingTupleStore{inner: store.NewMemoryStore(), order: order}
}

func (s *trackingTupleStore) Write(ctx context.Context, tuple model.Tuple) error {
	s.writes++
	*s.order = append(*s.order, "store_write")
	return s.inner.Write(ctx, tuple)
}

func (s *trackingTupleStore) Delete(ctx context.Context, tuple model.Tuple) error {
	s.deletes++
	*s.order = append(*s.order, "store_delete")
	return s.inner.Delete(ctx, tuple)
}

func (s *trackingTupleStore) DeleteIfAbove(ctx context.Context, tuple model.Tuple, min int) error {
	s.conditionalDeletes++
	*s.order = append(*s.order, "store_conditional_delete")
	return s.inner.DeleteIfAbove(ctx, tuple, min)
}

func (s *trackingTupleStore) WriteTx(ctx context.Context, writes, deletes []model.Tuple) error {
	s.transactions++
	*s.order = append(*s.order, "store_tx")
	return s.inner.WriteTx(ctx, writes, deletes)
}

func (s *trackingTupleStore) Read(ctx context.Context, filter model.TupleFilter) ([]model.Tuple, error) {
	return s.inner.Read(ctx, filter)
}

func (s *trackingTupleStore) ReadUsersets(
	ctx context.Context,
	objectType string,
	objectID string,
	relation string,
) ([]model.Tuple, error) {
	return s.inner.ReadUsersets(ctx, objectType, objectID, relation)
}

type precommitNotifier struct {
	order           *[]string
	writeErrorAt    int
	deleteErrorAt   int
	recordedWrites  []model.Tuple
	recordedDeletes []model.Tuple
	legacyWrites    []model.Tuple
	legacyDeletes   []model.Tuple
}

func (n *precommitNotifier) RecordTupleWrite(_ context.Context, tuple model.Tuple) error {
	n.recordedWrites = append(n.recordedWrites, tuple)
	*n.order = append(*n.order, "record_write")
	if n.writeErrorAt == len(n.recordedWrites) {
		return errPrecommitRecorder
	}
	return nil
}

func (n *precommitNotifier) RecordTupleDelete(_ context.Context, tuple model.Tuple) error {
	n.recordedDeletes = append(n.recordedDeletes, tuple)
	*n.order = append(*n.order, "record_delete")
	if n.deleteErrorAt == len(n.recordedDeletes) {
		return errPrecommitRecorder
	}
	return nil
}

func (n *precommitNotifier) OnTupleWrite(_ context.Context, tuple model.Tuple) {
	n.legacyWrites = append(n.legacyWrites, tuple)
	*n.order = append(*n.order, "notify_write")
}

func (n *precommitNotifier) OnTupleDelete(_ context.Context, tuple model.Tuple) {
	n.legacyDeletes = append(n.legacyDeletes, tuple)
	*n.order = append(*n.order, "notify_delete")
}

func (*precommitNotifier) OnModelUpdate(context.Context, string, *model.Model) {}

func newPrecommitTestEngine(
	t *testing.T,
	notifier *precommitNotifier,
) (*Engine, *trackingTupleStore) {
	t.Helper()
	tupleStore := newTrackingTupleStore(notifier.order)
	engine := New(tupleStore, nil, notifier)
	if err := engine.LoadModel([]byte(guardedModelYAML)); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	return engine, tupleStore
}

func assertNoLegacyTupleNotifications(t *testing.T, notifier *precommitNotifier) {
	t.Helper()
	if len(notifier.legacyWrites) != 0 || len(notifier.legacyDeletes) != 0 {
		t.Fatalf(
			"legacy notifications = %d writes, %d deletes; want none",
			len(notifier.legacyWrites),
			len(notifier.legacyDeletes),
		)
	}
}

func TestPrecommitRecorderFailurePreventsSingleTupleMutation(t *testing.T) {
	ctx := context.Background()

	t.Run("validated write", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order, writeErrorAt: 1}
		engine, tupleStore := newPrecommitTestEngine(t, notifier)

		err := engine.WriteTuple(ctx, "user:alice", "member", "org:acme")
		if !errors.Is(err, errPrecommitRecorder) {
			t.Fatalf("WriteTuple error = %v, want recorder error", err)
		}
		if tupleStore.writes != 0 {
			t.Fatalf("store writes = %d, want 0", tupleStore.writes)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})

	t.Run("unguarded delete", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order, deleteErrorAt: 1}
		engine, tupleStore := newPrecommitTestEngine(t, notifier)
		tuple := model.Tuple{
			ObjectType: "org", ObjectID: "acme", Relation: "member",
			UserType: "user", UserID: "alice",
		}
		if err := tupleStore.inner.Write(ctx, tuple); err != nil {
			t.Fatalf("seed tuple: %v", err)
		}

		err := engine.DeleteTuple(ctx, "user:alice", "member", "org:acme")
		if !errors.Is(err, errPrecommitRecorder) {
			t.Fatalf("DeleteTuple error = %v, want recorder error", err)
		}
		if tupleStore.deletes != 0 {
			t.Fatalf("store deletes = %d, want 0", tupleStore.deletes)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})

	t.Run("guarded delete", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order, deleteErrorAt: 1}
		engine, tupleStore := newPrecommitTestEngine(t, notifier)
		for _, userID := range []string{"alice", "bob"} {
			if err := tupleStore.inner.Write(ctx, model.Tuple{
				ObjectType: "org", ObjectID: "acme", Relation: "owner",
				UserType: "user", UserID: userID,
			}); err != nil {
				t.Fatalf("seed owner %s: %v", userID, err)
			}
		}

		err := engine.DeleteTuple(ctx, "user:alice", "owner", "org:acme")
		if !errors.Is(err, errPrecommitRecorder) {
			t.Fatalf("DeleteTuple error = %v, want recorder error", err)
		}
		if tupleStore.conditionalDeletes != 0 {
			t.Fatalf("conditional deletes = %d, want 0", tupleStore.conditionalDeletes)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})

	t.Run("raw write", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order, writeErrorAt: 1}
		engine, tupleStore := newPrecommitTestEngine(t, notifier)

		err := engine.WriteRawTuple(ctx, "user:alice", "member", "org:acme")
		if !errors.Is(err, errPrecommitRecorder) {
			t.Fatalf("WriteRawTuple error = %v, want recorder error", err)
		}
		if tupleStore.writes != 0 {
			t.Fatalf("store writes = %d, want 0", tupleStore.writes)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})

	t.Run("raw delete", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order, deleteErrorAt: 1}
		engine, tupleStore := newPrecommitTestEngine(t, notifier)

		err := engine.DeleteRawTuple(ctx, "user:alice", "member", "org:acme")
		if !errors.Is(err, errPrecommitRecorder) {
			t.Fatalf("DeleteRawTuple error = %v, want recorder error", err)
		}
		if tupleStore.deletes != 0 {
			t.Fatalf("store deletes = %d, want 0", tupleStore.deletes)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})
}

func TestPrecommitRecorderFailurePreventsBatchStoreMutation(t *testing.T) {
	ctx := context.Background()
	order := []string{}
	notifier := &precommitNotifier{order: &order, deleteErrorAt: 1}
	engine, tupleStore := newPrecommitTestEngine(t, notifier)
	writes := []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "alice"},
		{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "bob"},
	}
	deletes := []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "carol"},
	}
	if err := tupleStore.inner.Write(ctx, deletes[0]); err != nil {
		t.Fatalf("seed deleted tuple: %v", err)
	}

	err := engine.WriteRelationships(ctx, writes, deletes)
	if !errors.Is(err, errPrecommitRecorder) {
		t.Fatalf("WriteRelationships error = %v, want recorder error", err)
	}
	if tupleStore.transactions != 0 {
		t.Fatalf("store transactions = %d, want 0", tupleStore.transactions)
	}
	wantOrder := []string{"record_write", "record_write", "record_delete"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("operation order = %v, want %v", order, wantOrder)
	}
	assertNoLegacyTupleNotifications(t, notifier)
}

func TestPrecommitRecorderRunsBeforeStoreAndSuppressesLegacyNotifier(t *testing.T) {
	ctx := context.Background()

	t.Run("single write", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order}
		engine, _ := newPrecommitTestEngine(t, notifier)

		if err := engine.WriteTuple(ctx, "user:alice", "member", "org:acme"); err != nil {
			t.Fatalf("WriteTuple: %v", err)
		}
		wantOrder := []string{"record_write", "store_write"}
		if !reflect.DeepEqual(order, wantOrder) {
			t.Fatalf("operation order = %v, want %v", order, wantOrder)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})

	t.Run("batch", func(t *testing.T) {
		order := []string{}
		notifier := &precommitNotifier{order: &order}
		engine, _ := newPrecommitTestEngine(t, notifier)
		writes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "alice"},
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "bob"},
		}
		deletes := []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "carol"},
		}

		if err := engine.WriteRelationships(ctx, writes, deletes); err != nil {
			t.Fatalf("WriteRelationships: %v", err)
		}
		wantOrder := []string{"record_write", "record_write", "record_delete", "store_tx"}
		if !reflect.DeepEqual(order, wantOrder) {
			t.Fatalf("operation order = %v, want %v", order, wantOrder)
		}
		assertNoLegacyTupleNotifications(t, notifier)
	})
}

type orderedLegacyNotifier struct {
	order *[]string
}

func (n *orderedLegacyNotifier) OnTupleWrite(context.Context, model.Tuple) {
	*n.order = append(*n.order, "notify_write")
}

func (*orderedLegacyNotifier) OnTupleDelete(context.Context, model.Tuple)          {}
func (*orderedLegacyNotifier) OnModelUpdate(context.Context, string, *model.Model) {}

func TestLegacyNotifierStillRunsAfterStoreMutation(t *testing.T) {
	order := []string{}
	tupleStore := newTrackingTupleStore(&order)
	engine := New(tupleStore, nil, &orderedLegacyNotifier{order: &order})
	if err := engine.LoadModel([]byte(guardedModelYAML)); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	if err := engine.WriteTuple(context.Background(), "user:alice", "member", "org:acme"); err != nil {
		t.Fatalf("WriteTuple: %v", err)
	}
	wantOrder := []string{"store_write", "notify_write"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("operation order = %v, want %v", order, wantOrder)
	}
}

func TestReplaceRelationshipsRecorderFailureLeavesStoreUnchanged(t *testing.T) {
	ctx := context.Background()
	order := []string{}
	notifier := &precommitNotifier{order: &order, deleteErrorAt: 1}
	tupleStore := store.NewMemoryStore()
	engine := New(tupleStore, nil, notifier)
	if err := engine.LoadModel([]byte(guardedModelYAML)); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	seed := model.Tuple{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "alice"}
	if err := tupleStore.Write(ctx, seed); err != nil {
		t.Fatalf("seed tuple: %v", err)
	}
	replacement := model.Tuple{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "bob"}
	filter := model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user"}

	err := engine.ReplaceRelationships(ctx, filter, []model.Tuple{replacement})
	if !errors.Is(err, errPrecommitRecorder) {
		t.Fatalf("ReplaceRelationships error = %v, want recorder error", err)
	}
	got, err := tupleStore.Read(ctx, filter)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !reflect.DeepEqual(got, []model.Tuple{seed}) {
		t.Fatalf("tuples after failed replacement = %#v, want %#v", got, []model.Tuple{seed})
	}
	assertNoLegacyTupleNotifications(t, notifier)
}

func TestReplaceRelationshipsConcurrentCallsLeaveOneExactSet(t *testing.T) {
	ctx := context.Background()
	tupleStore := store.NewMemoryStore()
	engine := New(tupleStore, nil, nil)
	if err := engine.LoadModel([]byte(guardedModelYAML)); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	filter := model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user"}
	replacements := [][]model.Tuple{
		{{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "alice"}},
		{{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "bob"}},
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(replacements))
	for _, replacement := range replacements {
		wg.Add(1)
		go func(tuples []model.Tuple) {
			defer wg.Done()
			errs <- engine.ReplaceRelationships(ctx, filter, tuples)
		}(replacement)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("ReplaceRelationships: %v", err)
		}
	}

	got, err := tupleStore.Read(ctx, filter)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || (got[0].UserID != "alice" && got[0].UserID != "bob") {
		t.Fatalf("final tuples = %#v, want exactly one completed replacement", got)
	}
}
