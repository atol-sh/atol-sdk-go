package zanzibar

import (
	"context"
	"errors"
	"fmt"

	"atol.sh/sdk-go/zanzibar/check"
	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// ErrNotTransactional is returned by WriteRelationships when the underlying
// store does not implement store.TupleTxStore. There is no silent fallback to
// sequential single-tuple writes (ADR 0020).
var ErrNotTransactional = errors.New("store does not support transactional writes")

// ErrNotReplaceable is returned by ReplaceRelationships when the underlying
// store cannot serialize and atomically replace a bounded relationship set.
var ErrNotReplaceable = errors.New("store does not support transactional relationship replacement")

// minHolders returns the declared minimum-holder floor for (objectType,
// relation) under the resolved model, or 0 if there is no floor (or no model).
func (e *Engine) minHolders(ctx context.Context, objectType, relation string) int {
	tm := e.resolveModel(ctx, "")
	if tm == nil || tm.model == nil {
		return 0
	}
	typeDef, ok := tm.model.Types[objectType]
	if !ok {
		return 0
	}
	relDef, ok := typeDef.Relations[relation]
	if !ok {
		return 0
	}
	return relDef.MinHolders
}

// CanDelete reports whether the tuple (user, relation, object) could be deleted
// without breaching its relation's minimum-holder floor. It is read-only and
// never mutates the store: it returns model.ErrLastHolder if deleting the tuple
// would drop the direct-holder count to or below the floor, and nil otherwise.
// Used by the control plane's DeleteUser pre-scan (ADR 0016). Usersets
// (user_relation != "") and unguarded relations are always deletable.
func (e *Engine) CanDelete(ctx context.Context, user, relation, object string) error {
	userType, userID, userRelation := check.ParseUserKey(user)
	objectType, objectID := check.ParseObjectKey(object)

	min := e.minHolders(ctx, objectType, relation)
	if min < 1 || userRelation != "" {
		return nil
	}

	t := model.Tuple{
		ObjectType: objectType,
		ObjectID:   objectID,
		Relation:   relation,
		UserType:   userType,
		UserID:     userID,
	}

	// The tuple must actually exist for its deletion to threaten the floor:
	// deleting a missing tuple is a no-op and never a breach.
	existing, err := e.store.Read(ctx, model.TupleFilter{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: "",
	})
	if err != nil {
		return fmt.Errorf("read tuple %s#%s@%s: %w", object, relation, user, err)
	}
	if !containsDirect(existing, t) {
		return nil
	}

	count, err := e.directHolders(ctx, objectType, objectID, relation)
	if err != nil {
		return err
	}
	if count <= min {
		return model.ErrLastHolder
	}
	return nil
}

// directHolders counts the direct holders (user_relation == "") of
// (objectType, objectID, relation) in the store.
func (e *Engine) directHolders(ctx context.Context, objectType, objectID, relation string) (int, error) {
	tuples, err := e.store.Read(ctx, model.TupleFilter{
		ObjectType: objectType,
		ObjectID:   objectID,
		Relation:   relation,
	})
	if err != nil {
		return 0, fmt.Errorf("read holders %s:%s#%s: %w", objectType, objectID, relation, err)
	}
	count := 0
	for _, t := range tuples {
		if t.UserRelation == "" {
			count++
		}
	}
	return count, nil
}

// containsDirect reports whether want (a direct tuple) is present in tuples.
func containsDirect(tuples []model.Tuple, want model.Tuple) bool {
	for _, t := range tuples {
		if t.UserRelation == "" &&
			t.ObjectType == want.ObjectType && t.ObjectID == want.ObjectID &&
			t.Relation == want.Relation &&
			t.UserType == want.UserType && t.UserID == want.UserID {
			return true
		}
	}
	return false
}

// WriteRelationships applies writes and deletes atomically: all writes (upsert/
// idempotent) then all deletes (no-op when absent) in one store transaction,
// all-or-nothing (ADR 0020). Every write is model-validated before the
// transaction, so an invalid write aborts with zero side effects. A precommit
// recorder receives all writes then all deletes before the store transaction;
// otherwise notifier fan-out runs only after a successful commit. An empty batch is a no-op.
// Returns ErrNotTransactional if the store does not implement store.TupleTxStore.
func (e *Engine) WriteRelationships(ctx context.Context, writes, deletes []model.Tuple) error {
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}

	tx, ok := e.store.(store.TupleTxStore)
	if !ok {
		return ErrNotTransactional
	}

	// Validate every write against the resolved model before mutating anything.
	tm := e.resolveModel(ctx, "")
	if tm != nil && tm.model != nil {
		for _, t := range writes {
			if err := model.ValidateTuple(tm.model, t); err != nil {
				return fmt.Errorf("validate write %s#%s@%s: %w", t.ObjectKey(), t.Relation, t.UserKey(), err)
			}
		}
	}

	recorded := false
	for _, t := range writes {
		used, err := e.recordTupleWrite(ctx, t)
		if err != nil {
			return err
		}
		recorded = recorded || used
	}
	for _, t := range deletes {
		used, err := e.recordTupleDelete(ctx, t)
		if err != nil {
			return err
		}
		recorded = recorded || used
	}

	if err := tx.WriteTx(ctx, writes, deletes); err != nil {
		return fmt.Errorf("write tx: %w", err)
	}

	if !recorded {
		for _, t := range writes {
			e.notifier.OnTupleWrite(ctx, t)
		}
		for _, t := range deletes {
			e.notifier.OnTupleDelete(ctx, t)
		}
	}
	return nil
}

// ReplaceRelationships atomically replaces all tuples matching one bounded
// object/relation filter. Delta calculation happens after the store serializes
// concurrent replacements, so a completed call leaves exactly replacements.
// Precommit recorders run inside that transaction before any tuple mutation.
func (e *Engine) ReplaceRelationships(ctx context.Context, filter model.TupleFilter, replacements []model.Tuple) error {
	if filter.ObjectType == "" || filter.ObjectID == "" || filter.Relation == "" {
		return fmt.Errorf("replace relationships requires object_type, object_id, and relation")
	}

	tm := e.resolveModel(ctx, "")
	for _, tuple := range replacements {
		if !tupleMatchesFilter(tuple, filter) {
			return fmt.Errorf("replacement tuple %s#%s@%s does not match filter", tuple.ObjectKey(), tuple.Relation, tuple.UserKey())
		}
		if tm != nil && tm.model != nil {
			if err := model.ValidateTuple(tm.model, tuple); err != nil {
				return fmt.Errorf("validate replacement %s#%s@%s: %w", tuple.ObjectKey(), tuple.Relation, tuple.UserKey(), err)
			}
		}
	}

	replacer, ok := e.store.(store.TupleReplaceStore)
	if !ok {
		return ErrNotReplaceable
	}
	recorded := false
	writes, deletes, err := replacer.ReplaceTx(ctx, filter, replacements, func(writes, deletes []model.Tuple) error {
		for _, tuple := range writes {
			used, recordErr := e.recordTupleWrite(ctx, tuple)
			if recordErr != nil {
				return recordErr
			}
			recorded = recorded || used
		}
		for _, tuple := range deletes {
			used, recordErr := e.recordTupleDelete(ctx, tuple)
			if recordErr != nil {
				return recordErr
			}
			recorded = recorded || used
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("replace relationships: %w", err)
	}
	if !recorded {
		for _, tuple := range writes {
			e.notifier.OnTupleWrite(ctx, tuple)
		}
		for _, tuple := range deletes {
			e.notifier.OnTupleDelete(ctx, tuple)
		}
	}
	return nil
}

func tupleMatchesFilter(tuple model.Tuple, filter model.TupleFilter) bool {
	return (filter.ObjectType == "" || tuple.ObjectType == filter.ObjectType) &&
		(filter.ObjectID == "" || tuple.ObjectID == filter.ObjectID) &&
		(filter.Relation == "" || tuple.Relation == filter.Relation) &&
		(filter.UserType == "" || tuple.UserType == filter.UserType) &&
		(filter.UserID == "" || tuple.UserID == filter.UserID) &&
		(filter.UserRelation == "" || tuple.UserRelation == filter.UserRelation)
}
