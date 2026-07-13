// Package store provides tuple storage backends for the Zanzibar engine.
package store

import (
	"context"

	"atol.sh/sdk-go/zanzibar/model"
)

// TupleStore defines the interface for reading and writing relationship tuples.
type TupleStore interface {
	// Write persists a tuple. Returns an error if the tuple already exists
	// or fails model validation.
	Write(ctx context.Context, t model.Tuple) error

	// Delete removes a tuple. Returns nil if the tuple doesn't exist.
	Delete(ctx context.Context, t model.Tuple) error

	// Read returns tuples matching the filter. Empty filter fields match any value.
	Read(ctx context.Context, filter model.TupleFilter) ([]model.Tuple, error)

	// ReadUsersets returns tuples where the user column is a userset
	// (i.e., user_relation is non-empty) for the given object and relation.
	// Used during check traversal to find indirect relationships.
	ReadUsersets(ctx context.Context, objectType, objectID, relation string) ([]model.Tuple, error)
}

// TupleCounter is an optional interface that stores can implement to provide
// efficient tuple counts by object type. If a store does not implement this,
// Engine.CountTuples falls back to reading all tuples and counting in memory.
type TupleCounter interface {
	CountByObjectType(ctx context.Context) (map[string]int64, error)
}

// ConditionalDeleter is an optional capability for atomically enforcing a
// minimum-holder floor at delete time (ADR 0016). Stores that back a required
// relation must implement it; the engine fails loud if a guarded delete hits a
// store that does not.
type ConditionalDeleter interface {
	// DeleteIfAbove deletes t only if the object retains MORE THAN min DIRECT
	// holders (user_relation == "") of (object, relation). It returns
	// model.ErrLastHolder if the delete would drop the count to min or below.
	// Deleting a non-existent tuple is not a floor breach and returns nil.
	// The count and delete must be atomic against concurrent sibling deletes.
	DeleteIfAbove(ctx context.Context, t model.Tuple, min int) error
}

// TupleTxStore is an optional capability for applying a set of writes and
// deletes in one transaction (ADR 0020). Writes use upsert/idempotent
// semantics; deletes no-op when absent; the whole set is all-or-nothing.
type TupleTxStore interface {
	// WriteTx applies all writes then all deletes in ONE transaction.
	// Any error rolls back the whole set, leaving the store unchanged.
	WriteTx(ctx context.Context, writes, deletes []model.Tuple) error
}

// TuplePrecommit runs after a replacement store has serialized and computed
// the exact relationship delta, but before it mutates the store. Persistent
// implementations invoke it inside their transaction so durable audit records
// and relationship changes commit or roll back together.
type TuplePrecommit func(writes, deletes []model.Tuple) error

// TupleReplaceStore is an optional capability for replacing every tuple that
// matches one bounded object/relation filter. The store must serialize
// concurrent replacements, compute the exact delta while serialized, invoke
// precommit before mutation, and apply the delta atomically.
type TupleReplaceStore interface {
	ReplaceTx(
		ctx context.Context,
		filter model.TupleFilter,
		replacements []model.Tuple,
		precommit TuplePrecommit,
	) (writes, deletes []model.Tuple, err error)
}
