package store

import (
	"context"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
)

func TestContextTupleStore_ReadMergesContextTuples(t *testing.T) {
	inner := NewMemoryStore()
	ctx := context.Background()

	// Write a stored tuple.
	if err := inner.Write(ctx, model.Tuple{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
		UserType: "user", UserID: "alice",
	}); err != nil {
		t.Fatal(err)
	}

	// Context tuple adds another viewer.
	contextTuples := []model.Tuple{
		{ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
			UserType: "user", UserID: "bob"},
	}

	cs := NewContextTupleStore(inner, contextTuples)

	tuples, err := cs.Read(ctx, model.TupleFilter{
		ObjectType: "document", ObjectID: "doc1", Relation: "viewer",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(tuples) != 2 {
		t.Fatalf("expected 2 tuples, got %d", len(tuples))
	}

	users := map[string]bool{}
	for _, tp := range tuples {
		users[tp.UserID] = true
	}
	if !users["alice"] || !users["bob"] {
		t.Errorf("expected alice and bob, got %v", users)
	}
}

func TestContextTupleStore_ContextTuplesNotPersisted(t *testing.T) {
	inner := NewMemoryStore()
	ctx := context.Background()

	contextTuples := []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member",
			UserType: "user", UserID: "eve"},
	}

	cs := NewContextTupleStore(inner, contextTuples)

	// Context tuple should be visible through the context store.
	tuples, err := cs.Read(ctx, model.TupleFilter{
		ObjectType: "org", ObjectID: "acme", Relation: "member",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 1 {
		t.Fatalf("expected 1 context tuple, got %d", len(tuples))
	}

	// But not visible through the inner store directly.
	innerTuples, err := inner.Read(ctx, model.TupleFilter{
		ObjectType: "org", ObjectID: "acme", Relation: "member",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(innerTuples) != 0 {
		t.Fatalf("context tuple leaked to inner store: got %d tuples", len(innerTuples))
	}
}

func TestContextTupleStore_ReadUsersetsmergesContextTuples(t *testing.T) {
	inner := NewMemoryStore()
	ctx := context.Background()

	// Write a stored userset tuple.
	if err := inner.Write(ctx, model.Tuple{
		ObjectType: "project", ObjectID: "proj1", Relation: "admin",
		UserType: "team", UserID: "eng", UserRelation: "member",
	}); err != nil {
		t.Fatal(err)
	}

	// Context userset tuple.
	contextTuples := []model.Tuple{
		{ObjectType: "project", ObjectID: "proj1", Relation: "admin",
			UserType: "team", UserID: "ops", UserRelation: "lead"},
	}

	cs := NewContextTupleStore(inner, contextTuples)

	tuples, err := cs.ReadUsersets(ctx, "project", "proj1", "admin")
	if err != nil {
		t.Fatal(err)
	}

	if len(tuples) != 2 {
		t.Fatalf("expected 2 userset tuples, got %d", len(tuples))
	}
}

func TestContextTupleStore_FilterDoesNotMatchUnrelated(t *testing.T) {
	inner := NewMemoryStore()
	ctx := context.Background()

	contextTuples := []model.Tuple{
		{ObjectType: "document", ObjectID: "doc1", Relation: "editor",
			UserType: "user", UserID: "alice"},
		{ObjectType: "document", ObjectID: "doc2", Relation: "viewer",
			UserType: "user", UserID: "bob"},
	}

	cs := NewContextTupleStore(inner, contextTuples)

	// Only doc1 editor should match.
	tuples, err := cs.Read(ctx, model.TupleFilter{
		ObjectType: "document", ObjectID: "doc1", Relation: "editor",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple, got %d", len(tuples))
	}
	if tuples[0].UserID != "alice" {
		t.Errorf("expected alice, got %s", tuples[0].UserID)
	}
}

func TestContextTupleStore_WriteDelegatesToInner(t *testing.T) {
	inner := NewMemoryStore()
	ctx := context.Background()

	cs := NewContextTupleStore(inner, nil)

	tuple := model.Tuple{
		ObjectType: "org", ObjectID: "acme", Relation: "admin",
		UserType: "user", UserID: "alice",
	}

	if err := cs.Write(ctx, tuple); err != nil {
		t.Fatal(err)
	}

	// Should be visible in inner store.
	tuples, err := inner.Read(ctx, model.TupleFilter{
		ObjectType: "org", ObjectID: "acme", Relation: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple in inner store, got %d", len(tuples))
	}
}
