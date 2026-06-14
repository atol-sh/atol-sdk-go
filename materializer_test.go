package sdk

import (
	"context"
	"fmt"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

func TestMaterializerRegistry_MaterializeWritesToStore(t *testing.T) {
	s := store.NewMemoryStore()
	r := newMaterializerRegistry(s)
	ctx := context.Background()

	r.register("patients", func(ctx context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "profile", ObjectID: "p1", Relation: "patient",
				UserType: "patient", UserID: "rick"},
			{ObjectType: "profile", ObjectID: "p2", Relation: "patient",
				UserType: "patient", UserID: "morty"},
		}, nil
	})

	if err := r.materialize(ctx, "patients"); err != nil {
		t.Fatal(err)
	}

	// Materialized tuples should be visible via Read.
	tuples, err := s.Read(ctx, model.TupleFilter{
		ObjectType: "profile", Relation: "patient",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 2 {
		t.Fatalf("expected 2 materialized tuples, got %d", len(tuples))
	}
}

func TestMaterializerRegistry_RematerializeReplaces(t *testing.T) {
	s := store.NewMemoryStore()
	r := newMaterializerRegistry(s)
	ctx := context.Background()

	call := 0
	r.register("items", func(ctx context.Context) ([]model.Tuple, error) {
		call++
		if call == 1 {
			return []model.Tuple{
				{ObjectType: "item", ObjectID: "a", Relation: "owner",
					UserType: "user", UserID: "alice"},
			}, nil
		}
		return []model.Tuple{
			{ObjectType: "item", ObjectID: "b", Relation: "owner",
				UserType: "user", UserID: "bob"},
		}, nil
	})

	// First materialize
	if err := r.materialize(ctx, "items"); err != nil {
		t.Fatal(err)
	}
	tuples, _ := s.Read(ctx, model.TupleFilter{ObjectType: "item"})
	if len(tuples) != 1 || tuples[0].ObjectID != "a" {
		t.Fatalf("expected item a, got %v", tuples)
	}

	// Re-materialize — should replace, not append
	if err := r.materialize(ctx, "items"); err != nil {
		t.Fatal(err)
	}
	tuples, _ = s.Read(ctx, model.TupleFilter{ObjectType: "item"})
	if len(tuples) != 1 || tuples[0].ObjectID != "b" {
		t.Fatalf("expected item b after re-materialize, got %v", tuples)
	}
}

func TestMaterializerRegistry_ErrorHandling(t *testing.T) {
	s := store.NewMemoryStore()
	r := newMaterializerRegistry(s)
	ctx := context.Background()

	r.register("failing", func(ctx context.Context) ([]model.Tuple, error) {
		return nil, fmt.Errorf("db connection failed")
	})

	err := r.materialize(ctx, "failing")
	if err == nil {
		t.Fatal("expected error from failing materializer")
	}
}

func TestMaterializerRegistry_UnknownMaterializer(t *testing.T) {
	s := store.NewMemoryStore()
	r := newMaterializerRegistry(s)
	ctx := context.Background()

	err := r.materialize(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown materializer")
	}
}

func TestMaterializerRegistry_MaterializeAll(t *testing.T) {
	s := store.NewMemoryStore()
	r := newMaterializerRegistry(s)
	ctx := context.Background()

	r.register("orgs", func(ctx context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "member",
				UserType: "user", UserID: "alice"},
		}, nil
	})

	r.register("teams", func(ctx context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "team", ObjectID: "eng", Relation: "member",
				UserType: "user", UserID: "bob"},
		}, nil
	})

	if err := r.materializeAll(ctx); err != nil {
		t.Fatal(err)
	}

	// Both materializers should have produced results.
	orgTuples, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org"})
	teamTuples, _ := s.Read(ctx, model.TupleFilter{ObjectType: "team"})

	if len(orgTuples) != 1 {
		t.Errorf("expected 1 org tuple, got %d", len(orgTuples))
	}
	if len(teamTuples) != 1 {
		t.Errorf("expected 1 team tuple, got %d", len(teamTuples))
	}
}

func TestMaterializerRegistry_ClearMaterialized(t *testing.T) {
	s := store.NewMemoryStore()
	r := newMaterializerRegistry(s)
	ctx := context.Background()

	r.register("data", func(ctx context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "resource", ObjectID: "r1", Relation: "viewer",
				UserType: "user", UserID: "alice"},
		}, nil
	})

	if err := r.materialize(ctx, "data"); err != nil {
		t.Fatal(err)
	}

	// Should be visible.
	tuples, _ := s.Read(ctx, model.TupleFilter{ObjectType: "resource"})
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple, got %d", len(tuples))
	}

	// Clear and verify gone.
	s.ClearMaterialized("data")
	tuples, _ = s.Read(ctx, model.TupleFilter{ObjectType: "resource"})
	if len(tuples) != 0 {
		t.Fatalf("expected 0 tuples after clear, got %d", len(tuples))
	}
}
