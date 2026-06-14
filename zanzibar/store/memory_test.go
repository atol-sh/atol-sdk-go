package store

import (
	"context"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
)

func TestMemoryStore_WriteAndRead(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	tuple := model.Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "alice",
	}

	if err := s.Write(ctx, tuple); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	// Read with exact filter.
	got, err := s.Read(ctx, model.TupleFilter{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
	})
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Read() returned %d tuples, want 1", len(got))
	}
	if got[0].UserID != "alice" {
		t.Errorf("UserID = %q, want %q", got[0].UserID, "alice")
	}
}

func TestMemoryStore_WriteDeduplicates(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	tuple := model.Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "alice",
	}

	s.Write(ctx, tuple)
	s.Write(ctx, tuple) // duplicate

	got, _ := s.Read(ctx, model.TupleFilter{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
	})
	if len(got) != 1 {
		t.Errorf("Read() returned %d tuples after duplicate write, want 1", len(got))
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	tuple := model.Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "alice",
	}

	s.Write(ctx, tuple)
	if err := s.Delete(ctx, tuple); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	got, _ := s.Read(ctx, model.TupleFilter{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
	})
	if len(got) != 0 {
		t.Errorf("Read() returned %d tuples after delete, want 0", len(got))
	}
}

func TestMemoryStore_DeleteNonExistent(t *testing.T) {
	s := NewMemoryStore()

	// Deleting a non-existent tuple should not error.
	err := s.Delete(context.Background(), model.Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "ghost",
	})
	if err != nil {
		t.Fatalf("Delete(non-existent) error: %v", err)
	}
}

func TestMemoryStore_ReadWithPartialFilter(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Write tuples for different users on the same document.
	s.Write(ctx, model.Tuple{ObjectType: "document", ObjectID: "doc-1", Relation: "editor", UserType: "user", UserID: "alice"})
	s.Write(ctx, model.Tuple{ObjectType: "document", ObjectID: "doc-1", Relation: "viewer", UserType: "user", UserID: "bob"})
	s.Write(ctx, model.Tuple{ObjectType: "document", ObjectID: "doc-2", Relation: "editor", UserType: "user", UserID: "alice"})

	// Filter by user only (slow path — scans all tuples).
	got, _ := s.Read(ctx, model.TupleFilter{UserType: "user", UserID: "alice"})
	if len(got) != 2 {
		t.Errorf("Read(user=alice) returned %d tuples, want 2", len(got))
	}

	// Filter by object type + ID + relation (fast path — indexed).
	got, _ = s.Read(ctx, model.TupleFilter{ObjectType: "document", ObjectID: "doc-1", Relation: "editor"})
	if len(got) != 1 {
		t.Errorf("Read(doc-1, editor) returned %d tuples, want 1", len(got))
	}

	// Filter with user narrowing on indexed path.
	got, _ = s.Read(ctx, model.TupleFilter{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "nobody",
	})
	if len(got) != 0 {
		t.Errorf("Read(nobody) returned %d tuples, want 0", len(got))
	}
}

func TestMemoryStore_ReadUsersets(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Direct user — should NOT be returned by ReadUsersets.
	s.Write(ctx, model.Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
		UserType: "user", UserID: "alice",
	})

	// Userset — SHOULD be returned.
	s.Write(ctx, model.Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
		UserType: "org", UserID: "acme", UserRelation: "member",
	})

	got, err := s.ReadUsersets(ctx, "document", "doc-1", "viewer")
	if err != nil {
		t.Fatalf("ReadUsersets() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ReadUsersets() returned %d, want 1 (usersets only)", len(got))
	}
	if got[0].UserRelation != "member" {
		t.Errorf("UserRelation = %q, want %q", got[0].UserRelation, "member")
	}
}

func TestMemoryStore_WriteMaterialized(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	tuples := []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "alice"},
		{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "bob"},
	}

	s.WriteMaterialized("org-sync", tuples)

	// Materialized tuples should appear in Read results.
	got, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member"})
	if len(got) != 2 {
		t.Errorf("Read() returned %d tuples after WriteMaterialized, want 2", len(got))
	}

	// Replace with new set.
	s.WriteMaterialized("org-sync", []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member", UserType: "user", UserID: "charlie"},
	})

	got, _ = s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member"})
	if len(got) != 1 {
		t.Errorf("Read() returned %d tuples after re-materialization, want 1", len(got))
	}
	if got[0].UserID != "charlie" {
		t.Errorf("UserID = %q, want %q", got[0].UserID, "charlie")
	}
}

func TestMemoryStore_ClearMaterialized(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.WriteMaterialized("sync", []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "owner", UserType: "user", UserID: "alice"},
	})

	s.ClearMaterialized("sync")

	got, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme"})
	if len(got) != 0 {
		t.Errorf("Read() returned %d tuples after ClearMaterialized, want 0", len(got))
	}
}

func TestMemoryStore_MaterializedUsersets(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	// Materialized userset tuples should appear in ReadUsersets.
	s.WriteMaterialized("hierarchy", []model.Tuple{
		{ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
			UserType: "org", UserID: "acme", UserRelation: "member"},
	})

	got, err := s.ReadUsersets(ctx, "document", "doc-1", "viewer")
	if err != nil {
		t.Fatalf("ReadUsersets() error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("ReadUsersets() returned %d, want 1 (materialized userset)", len(got))
	}
}
