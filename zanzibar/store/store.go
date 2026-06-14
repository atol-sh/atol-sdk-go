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
