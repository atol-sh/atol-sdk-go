package zanzibar

import (
	"context"
	"errors"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

const modelOperationPermissiveYAML = `version: "1.0"
types:
  user: {}
  document:
    relations:
      viewer:
        types: [user]
`

const modelOperationRestrictiveYAML = `version: "1.0"
types:
  user: {}
  document: {}
`

var errModelRefreshUnavailable = errors.New("model store unavailable")

type failingGetModelStore struct {
	*modelCommitStore
	getErr error
}

func (s *failingGetModelStore) Get(ctx context.Context, tenantID string) (store.StoredModel, error) {
	if s.getErr != nil {
		return store.StoredModel{}, s.getErr
	}
	return s.modelCommitStore.Get(ctx, tenantID)
}

func TestModelDependentCheckRefreshesAcrossReplicasWithoutStream(t *testing.T) {
	modelStore := newModelCommitStore()
	tupleStore := store.NewMemoryStore()
	writer := New(tupleStore, modelStore, nil)
	reader := New(tupleStore, modelStore, nil)
	ctx := store.ContextWithTenant(context.Background(), "tenant-a")

	if err := writer.LoadModelForTenant(ctx, "tenant-a", []byte(modelOperationPermissiveYAML)); err != nil {
		t.Fatalf("publish permissive model: %v", err)
	}
	if err := reader.LoadPersistedModels(ctx); err != nil {
		t.Fatalf("seed reader cache: %v", err)
	}
	if err := reader.WriteRawTuple(ctx, "user:alice", "viewer", "document:roadmap"); err != nil {
		t.Fatalf("seed tuple: %v", err)
	}
	allowed, err := reader.Check(ctx, "user:alice", "viewer", "document:roadmap")
	if err != nil || !allowed {
		t.Fatalf("permissive check = (%v, %v), want allowed", allowed, err)
	}

	if err := writer.LoadModelForTenant(ctx, "tenant-a", []byte(modelOperationRestrictiveYAML)); err != nil {
		t.Fatalf("publish restrictive model: %v", err)
	}
	allowed, err = reader.Check(ctx, "user:alice", "viewer", "document:roadmap")
	if err != nil {
		t.Fatalf("check restrictive model: %v", err)
	}
	if allowed {
		t.Fatal("reader retained stale permissive authorization after restrictive publish")
	}
	if got := reader.ModelRevisionForTenant(ctx, "tenant-a"); got != 2 {
		t.Fatalf("reader revision = %d, want 2", got)
	}
}

func TestModelDependentOperationsFailClosedWhenRefreshFails(t *testing.T) {
	baseStore := newModelCommitStore()
	modelStore := &failingGetModelStore{modelCommitStore: baseStore}
	tupleStore := store.NewMemoryStore()
	engine := New(tupleStore, modelStore, nil)
	ctx := store.ContextWithTenant(context.Background(), "tenant-a")

	if err := engine.LoadModelForTenant(ctx, "tenant-a", []byte(modelOperationPermissiveYAML)); err != nil {
		t.Fatalf("seed model: %v", err)
	}
	before := engine.ModelSnapshotForTenant(ctx, "tenant-a")
	modelStore.getErr = errModelRefreshUnavailable
	tuple := model.Tuple{
		ObjectType: "document", ObjectID: "roadmap", Relation: "viewer",
		UserType: "user", UserID: "alice",
	}

	operations := []struct {
		name string
		run  func() error
	}{
		{name: "check", run: func() error {
			_, err := engine.Check(ctx, "user:alice", "viewer", "document:roadmap")
			return err
		}},
		{name: "check with context", run: func() error {
			_, err := engine.CheckWithContextTuples(ctx, "user:alice", "viewer", "document:roadmap", []model.Tuple{tuple})
			return err
		}},
		{name: "write tuple", run: func() error {
			return engine.WriteTuple(ctx, "user:alice", "viewer", "document:roadmap")
		}},
		{name: "delete tuple", run: func() error {
			return engine.DeleteTuple(ctx, "user:alice", "viewer", "document:roadmap")
		}},
		{name: "can delete", run: func() error {
			return engine.CanDelete(ctx, "user:alice", "viewer", "document:roadmap")
		}},
		{name: "write relationships", run: func() error {
			return engine.WriteRelationships(ctx, []model.Tuple{tuple}, nil)
		}},
		{name: "replace relationships", run: func() error {
			return engine.ReplaceRelationships(ctx, model.TupleFilter{
				ObjectType: "document", ObjectID: "roadmap", Relation: "viewer",
			}, []model.Tuple{tuple})
		}},
		{name: "list objects", run: func() error {
			_, err := engine.ListObjects(ctx, "user:alice", "viewer", "document")
			return err
		}},
		{name: "list users", run: func() error {
			_, err := engine.ListUsers(ctx, "viewer", "document:roadmap")
			return err
		}},
		{name: "debug", run: func() error {
			_, _, err := engine.CheckDebug(ctx, "user:alice", "viewer", "document:roadmap")
			return err
		}},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !errors.Is(err, errModelRefreshUnavailable) {
				t.Fatalf("operation error = %v, want model refresh failure", err)
			}
		})
	}

	after := engine.ModelSnapshotForTenant(ctx, "tenant-a")
	if after.Revision != before.Revision || string(after.YAML) != string(before.YAML) {
		t.Fatalf("failed refresh changed active cache: before %+v after %+v", before, after)
	}
	tuples, err := engine.ReadTuples(ctx, model.TupleFilter{})
	if err != nil {
		t.Fatalf("read tuples: %v", err)
	}
	if len(tuples) != 0 {
		t.Fatalf("failed refresh mutated tuples: %+v", tuples)
	}
}

func TestRefreshModelForContextKeepsEmbeddedEngineLocal(t *testing.T) {
	engine := New(store.NewMemoryStore(), nil, nil)
	if err := engine.LoadModel([]byte(modelOperationPermissiveYAML)); err != nil {
		t.Fatalf("load embedded model: %v", err)
	}

	compiled, err := engine.RefreshModelForContext(context.Background())
	if err != nil {
		t.Fatalf("refresh embedded model: %v", err)
	}
	if compiled == nil || compiled.Types["document"] == nil {
		t.Fatal("embedded model was not returned")
	}
}
