package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
)

func TestMemoryStoreReadPageUsesStableFullTupleOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	input := []model.Tuple{
		{ObjectType: "folder", ObjectID: "b", Relation: "viewer", UserType: "user", UserID: "alice"},
		{ObjectType: "document", ObjectID: "a", Relation: "owner", UserType: "user", UserID: "zoe"},
		{ObjectType: "document", ObjectID: "a", Relation: "owner", UserType: "team", UserID: "ops", UserRelation: "member"},
		{ObjectType: "document", ObjectID: "a", Relation: "owner", UserType: "team", UserID: "ops"},
	}
	for _, tuple := range input {
		if err := store.Write(ctx, tuple); err != nil {
			t.Fatalf("write tuple: %v", err)
		}
	}

	var got []model.Tuple
	var cursor string
	for {
		page, next, err := store.ReadPage(ctx, model.TupleFilter{}, cursor, 2)
		if err != nil {
			t.Fatalf("read page: %v", err)
		}
		got = append(got, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	want := []model.Tuple{input[3], input[2], input[1], input[0]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered scan = %#v, want %#v", got, want)
	}
}

func TestTuplePageCursorRejectsScopeFilterAndShapeChanges(t *testing.T) {
	t.Parallel()
	filter := model.TupleFilter{UserType: "user", UserID: "alice"}
	tuple := model.Tuple{ObjectType: "document", ObjectID: "a", Relation: "viewer", UserType: "user", UserID: "alice"}
	cursor, err := EncodeTuplePageCursor("tenant-a", filter, tuple)
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}

	for name, candidate := range map[string]struct {
		scope  string
		filter model.TupleFilter
		cursor string
	}{
		"tenant": {"tenant-b", filter, cursor},
		"filter": {"tenant-a", model.TupleFilter{UserType: "user", UserID: "bob"}, cursor},
		"shape":  {"tenant-a", filter, cursor + "junk"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeTuplePageCursor(candidate.cursor, candidate.scope, candidate.filter)
			if !errors.Is(err, ErrInvalidTuplePageCursor) {
				t.Fatalf("DecodeTuplePageCursor() error = %v, want ErrInvalidTuplePageCursor", err)
			}
		})
	}
}

func TestMemoryStoreReadPageRejectsInvalidLimitAndCursor(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	if _, _, err := store.ReadPage(context.Background(), model.TupleFilter{}, "", 0); !errors.Is(err, ErrInvalidTuplePageLimit) {
		t.Fatalf("zero limit error = %v", err)
	}
	if _, _, err := store.ReadPage(context.Background(), model.TupleFilter{}, "not-a-cursor", 1); !errors.Is(err, ErrInvalidTuplePageCursor) {
		t.Fatalf("bad cursor error = %v", err)
	}
}

func TestInsertBoundedPageTupleNeverRetainsTenantSizedInput(t *testing.T) {
	t.Parallel()
	page := make([]model.Tuple, 0, 3)
	for i := 99; i >= 0; i-- {
		page = insertBoundedPageTuple(page, model.Tuple{
			ObjectType: "document", ObjectID: fmt.Sprintf("%03d", i), Relation: "viewer",
			UserType: "user", UserID: "alice",
		}, model.Tuple{}, false, 3)
		if len(page) > 3 {
			t.Fatalf("bounded page retained %d tuples, want at most 3", len(page))
		}
	}
	if got := []string{page[0].ObjectID, page[1].ObjectID, page[2].ObjectID}; !reflect.DeepEqual(got, []string{"000", "001", "002"}) {
		t.Fatalf("bounded selection = %v, want smallest ordered tuples", got)
	}
}
