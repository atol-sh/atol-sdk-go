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
// transaction, so an invalid write aborts with zero side effects. The notifier
// fan-out (OnTupleWrite per write, then OnTupleDelete per delete) runs only
// after a successful commit, never on error. An empty batch is a no-op.
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

	if err := tx.WriteTx(ctx, writes, deletes); err != nil {
		return fmt.Errorf("write tx: %w", err)
	}

	for _, t := range writes {
		e.notifier.OnTupleWrite(ctx, t)
	}
	for _, t := range deletes {
		e.notifier.OnTupleDelete(ctx, t)
	}
	return nil
}
