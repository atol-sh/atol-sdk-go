package store

import (
	"context"

	"atol.sh/sdk-go/zanzibar/model"
)

// ContextTupleStore wraps a TupleStore and overlays ephemeral context tuples
// for read operations. Context tuples are never persisted — they exist only
// for the duration of a single authorization check. Write and Delete
// operations delegate directly to the inner store.
type ContextTupleStore struct {
	inner   TupleStore
	context []model.Tuple
}

// NewContextTupleStore creates a ContextTupleStore that overlays the given
// context tuples on top of the inner store's results.
func NewContextTupleStore(inner TupleStore, contextTuples []model.Tuple) *ContextTupleStore {
	return &ContextTupleStore{
		inner:   inner,
		context: contextTuples,
	}
}

// Write delegates to the inner store. Context tuples are never written.
func (s *ContextTupleStore) Write(ctx context.Context, t model.Tuple) error {
	return s.inner.Write(ctx, t)
}

// Delete delegates to the inner store.
func (s *ContextTupleStore) Delete(ctx context.Context, t model.Tuple) error {
	return s.inner.Delete(ctx, t)
}

// Read returns tuples from both the inner store and the context tuples
// that match the filter. Context tuples are merged via linear scan.
func (s *ContextTupleStore) Read(ctx context.Context, filter model.TupleFilter) ([]model.Tuple, error) {
	inner, err := s.inner.Read(ctx, filter)
	if err != nil {
		return nil, err
	}

	for _, t := range s.context {
		if matchesTupleFilter(t, filter) {
			inner = append(inner, t)
		}
	}

	return inner, nil
}

// ReadUsersets returns userset tuples from both the inner store and the
// context tuples for the given object and relation.
func (s *ContextTupleStore) ReadUsersets(ctx context.Context, objectType, objectID, relation string) ([]model.Tuple, error) {
	inner, err := s.inner.ReadUsersets(ctx, objectType, objectID, relation)
	if err != nil {
		return nil, err
	}

	for _, t := range s.context {
		if t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == relation && t.UserRelation != "" {
			inner = append(inner, t)
		}
	}

	return inner, nil
}

// matchesTupleFilter checks if a tuple matches the given filter.
func matchesTupleFilter(t model.Tuple, f model.TupleFilter) bool {
	if f.ObjectType != "" && t.ObjectType != f.ObjectType {
		return false
	}
	if f.ObjectID != "" && t.ObjectID != f.ObjectID {
		return false
	}
	if f.Relation != "" && t.Relation != f.Relation {
		return false
	}
	if f.UserType != "" && t.UserType != f.UserType {
		return false
	}
	if f.UserID != "" && t.UserID != f.UserID {
		return false
	}
	if f.UserRelation != "" && t.UserRelation != f.UserRelation {
		return false
	}
	return true
}
