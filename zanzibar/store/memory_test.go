package store

import (
	"context"
	"errors"
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

// orgOwner returns a direct org:acme#owner tuple for the given user id.
func orgOwner(id string) model.Tuple {
	return model.Tuple{ObjectType: "org", ObjectID: "acme", Relation: "owner", UserType: "user", UserID: id}
}

func TestMemoryStore_DeleteIfAbove(t *testing.T) {
	ctx := context.Background()

	t.Run("above floor deletes", func(t *testing.T) {
		s := NewMemoryStore()
		s.Write(ctx, orgOwner("alice"))
		s.Write(ctx, orgOwner("bob"))

		if err := s.DeleteIfAbove(ctx, orgOwner("alice"), 1); err != nil {
			t.Fatalf("DeleteIfAbove(2 holders, min 1) error: %v, want nil", err)
		}
		got, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "owner"})
		if len(got) != 1 {
			t.Errorf("holders after delete = %d, want 1", len(got))
		}
	})

	t.Run("at floor refuses", func(t *testing.T) {
		s := NewMemoryStore()
		s.Write(ctx, orgOwner("alice"))

		err := s.DeleteIfAbove(ctx, orgOwner("alice"), 1)
		if !errors.Is(err, model.ErrLastHolder) {
			t.Fatalf("DeleteIfAbove(1 holder, min 1) error = %v, want ErrLastHolder", err)
		}
		got, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "owner"})
		if len(got) != 1 {
			t.Errorf("holders after refused delete = %d, want 1 (tuple preserved)", len(got))
		}
	})

	t.Run("missing tuple is not a breach", func(t *testing.T) {
		s := NewMemoryStore()
		s.Write(ctx, orgOwner("alice"))

		// Deleting a different (absent) tuple must not error even at the floor.
		if err := s.DeleteIfAbove(ctx, orgOwner("ghost"), 1); err != nil {
			t.Fatalf("DeleteIfAbove(missing tuple) error = %v, want nil", err)
		}
		got, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "owner"})
		if len(got) != 1 {
			t.Errorf("holders = %d, want 1 (unchanged)", len(got))
		}
	})

	t.Run("usersets do not count toward floor", func(t *testing.T) {
		s := NewMemoryStore()
		// One direct holder plus one userset holder.
		s.Write(ctx, orgOwner("alice"))
		s.Write(ctx, model.Tuple{ObjectType: "org", ObjectID: "acme", Relation: "owner",
			UserType: "team", UserID: "eng", UserRelation: "member"})

		// Only 1 direct holder, so deleting it breaches the floor of 1.
		err := s.DeleteIfAbove(ctx, orgOwner("alice"), 1)
		if !errors.Is(err, model.ErrLastHolder) {
			t.Fatalf("error = %v, want ErrLastHolder (userset must not pad the direct count)", err)
		}
	})
}

func TestMemoryStore_WriteTx(t *testing.T) {
	ctx := context.Background()

	t.Run("applies writes then deletes", func(t *testing.T) {
		s := NewMemoryStore()
		// Seed two tuples that the tx will delete.
		s.Write(ctx, orgOwner("old1"))
		s.Write(ctx, orgOwner("old2"))

		writes := []model.Tuple{orgOwner("new1"), orgOwner("new2"), orgOwner("new3")}
		deletes := []model.Tuple{orgOwner("old1"), orgOwner("old2")}

		if err := s.WriteTx(ctx, writes, deletes); err != nil {
			t.Fatalf("WriteTx() error: %v", err)
		}

		got, _ := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "owner"})
		if len(got) != 3 {
			t.Errorf("holders after tx = %d, want 3", len(got))
		}
		ids := map[string]bool{}
		for _, x := range got {
			ids[x.UserID] = true
		}
		for _, want := range []string{"new1", "new2", "new3"} {
			if !ids[want] {
				t.Errorf("missing written tuple for %q", want)
			}
		}
		for _, gone := range []string{"old1", "old2"} {
			if ids[gone] {
				t.Errorf("deleted tuple for %q still present", gone)
			}
		}
	})

	t.Run("delete of absent tuple is a no-op", func(t *testing.T) {
		s := NewMemoryStore()
		if err := s.WriteTx(ctx, nil, []model.Tuple{orgOwner("ghost")}); err != nil {
			t.Fatalf("WriteTx(absent delete) error: %v", err)
		}
	})
}
