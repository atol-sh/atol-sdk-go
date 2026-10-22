// Package store provides tuple storage backends for the Zanzibar engine.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"atol.sh/sdk-go/zanzibar/model"
)

const (
	// MaxTuplePageSize is the largest bounded relationship page a store may
	// return. Callers must continue with the returned cursor for larger scans.
	MaxTuplePageSize  = 500
	maxTupleCursorLen = 4096
)

var (
	ErrInvalidTuplePageLimit  = errors.New("tuple page limit must be between 1 and 500")
	ErrInvalidTuplePageCursor = errors.New("invalid tuple page cursor")
	ErrTuplePageUnsupported   = errors.New("tuple store does not support bounded tuple pages")
)

// TuplePageStore is the bounded keyset-scanning capability used for durable
// maintenance workflows. Results must use TupleLess ordering and cursors must
// be bound to both the tenant scope and the exact filter.
type TuplePageStore interface {
	ReadPage(ctx context.Context, filter model.TupleFilter, cursor string, limit int) ([]model.Tuple, string, error)
	CursorAfter(ctx context.Context, filter model.TupleFilter, tuple model.Tuple) (string, error)
}

// TupleSubjectExcludingPageStore supports a bounded scan that omits one exact
// subject. It lets union scans avoid cross-filter duplicates durably.
type TupleSubjectExcludingPageStore interface {
	ReadPageExcludingSubject(ctx context.Context, filter model.TupleFilter, excludedUserType,
		excludedUserID, cursor string, limit int) ([]model.Tuple, string, error)
	CursorAfterExcludingSubject(ctx context.Context, filter model.TupleFilter, excludedUserType,
		excludedUserID string, tuple model.Tuple) (string, error)
}

// ExcludingSubjectCursorScope binds a cursor to an exact exclusion predicate.
func ExcludingSubjectCursorScope(tenantScope, userType, userID string) string {
	return tenantScope + "\x00exclude-subject\x00" + userType + "\x00" + userID
}

type tuplePageCursor struct {
	Version int       `json:"v"`
	Scope   string    `json:"s"`
	Key     [6]string `json:"k"`
}

// ValidateTuplePageLimit rejects unbounded or oversized page requests.
func ValidateTuplePageLimit(limit int) error {
	if limit < 1 || limit > MaxTuplePageSize {
		return ErrInvalidTuplePageLimit
	}
	return nil
}

// EncodeTuplePageCursor returns an opaque cursor bound to tenantScope and the
// exact filter. tenantScope must be the store's resolved tenant identifier.
func EncodeTuplePageCursor(tenantScope string, filter model.TupleFilter, tuple model.Tuple) (string, error) {
	if !matchesTupleFilter(tuple, filter) {
		return "", fmt.Errorf("%w: key does not match filter", ErrInvalidTuplePageCursor)
	}
	cursor := tuplePageCursor{
		Version: 1,
		Scope:   tuplePageScope(tenantScope, filter),
		Key: [6]string{
			tuple.ObjectType,
			tuple.ObjectID,
			tuple.Relation,
			tuple.UserType,
			tuple.UserID,
			tuple.UserRelation,
		},
	}
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode tuple page cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeTuplePageCursor validates a cursor's shape, version, tenant scope,
// exact filter binding, and last key before returning that key.
func DecodeTuplePageCursor(cursor, tenantScope string, filter model.TupleFilter) (model.Tuple, error) {
	if cursor == "" || len(cursor) > maxTupleCursorLen {
		return model.Tuple{}, ErrInvalidTuplePageCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return model.Tuple{}, ErrInvalidTuplePageCursor
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var decoded tuplePageCursor
	if err := decoder.Decode(&decoded); err != nil {
		return model.Tuple{}, ErrInvalidTuplePageCursor
	}
	if err := ensureCursorEOF(decoder); err != nil {
		return model.Tuple{}, err
	}
	if decoded.Version != 1 || decoded.Scope != tuplePageScope(tenantScope, filter) {
		return model.Tuple{}, ErrInvalidTuplePageCursor
	}
	tuple := model.Tuple{
		ObjectType: decoded.Key[0], ObjectID: decoded.Key[1], Relation: decoded.Key[2],
		UserType: decoded.Key[3], UserID: decoded.Key[4], UserRelation: decoded.Key[5],
	}
	if !matchesTupleFilter(tuple, filter) {
		return model.Tuple{}, ErrInvalidTuplePageCursor
	}
	return tuple, nil
}

func ensureCursorEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidTuplePageCursor
	}
	return nil
}

func tuplePageScope(tenantScope string, filter model.TupleFilter) string {
	value := strings.Join([]string{
		tenantScope, filter.ObjectType, filter.ObjectID, filter.Relation,
		filter.UserType, filter.UserID, filter.UserRelation,
	}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// TupleLess defines the stable full-key ordering required by TuplePageStore.
func TupleLess(left, right model.Tuple) bool {
	leftKey := [...]string{left.ObjectType, left.ObjectID, left.Relation, left.UserType, left.UserID, left.UserRelation}
	rightKey := [...]string{right.ObjectType, right.ObjectID, right.Relation, right.UserType, right.UserID, right.UserRelation}
	for i := range leftKey {
		if leftKey[i] != rightKey[i] {
			return leftKey[i] < rightKey[i]
		}
	}
	return false
}

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
