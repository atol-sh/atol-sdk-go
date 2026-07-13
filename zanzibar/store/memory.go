package store

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"atol.sh/sdk-go/zanzibar/model"
)

// MemoryStore is a thread-safe in-memory tuple store.
// Indexed by (objectType, objectID, relation) for efficient check lookups.
type MemoryStore struct {
	mu sync.RWMutex

	// Primary index: "objectType:objectID#relation" → set of tuples
	byObjectRelation map[string]map[string]model.Tuple

	// Secondary index: "userType:userID" → set of tuple keys
	byUser map[string]map[string]bool

	// Materialized tuples keyed by materializer name.
	materialized map[string][]model.Tuple
}

// NewMemoryStore creates an in-memory tuple store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byObjectRelation: make(map[string]map[string]model.Tuple),
		byUser:           make(map[string]map[string]bool),
	}
}

func tupleKey(t model.Tuple) string {
	return fmt.Sprintf("%s:%s#%s@%s:%s#%s", t.ObjectType, t.ObjectID, t.Relation, t.UserType, t.UserID, t.UserRelation)
}

func objectRelationKey(objectType, objectID, relation string) string {
	return objectType + ":" + objectID + "#" + relation
}

func (s *MemoryStore) Write(_ context.Context, t model.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeLocked(t)
	return nil
}

// writeLocked inserts t into both indexes. The caller must hold s.mu.
func (s *MemoryStore) writeLocked(t model.Tuple) {
	orKey := objectRelationKey(t.ObjectType, t.ObjectID, t.Relation)
	tk := tupleKey(t)

	if s.byObjectRelation[orKey] == nil {
		s.byObjectRelation[orKey] = make(map[string]model.Tuple)
	}

	s.byObjectRelation[orKey][tk] = t

	userKey := t.UserType + ":" + t.UserID
	if s.byUser[userKey] == nil {
		s.byUser[userKey] = make(map[string]bool)
	}
	s.byUser[userKey][tk] = true
}

func (s *MemoryStore) Delete(_ context.Context, t model.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(t)
	return nil
}

// deleteLocked removes t from both indexes. The caller must hold s.mu.
func (s *MemoryStore) deleteLocked(t model.Tuple) {
	orKey := objectRelationKey(t.ObjectType, t.ObjectID, t.Relation)
	tk := tupleKey(t)

	if tuples, ok := s.byObjectRelation[orKey]; ok {
		delete(tuples, tk)
		if len(tuples) == 0 {
			delete(s.byObjectRelation, orKey)
		}
	}

	userKey := t.UserType + ":" + t.UserID
	if keys, ok := s.byUser[userKey]; ok {
		delete(keys, tk)
		if len(keys) == 0 {
			delete(s.byUser, userKey)
		}
	}
}

// directHoldersLocked counts the direct holders (user_relation == "") of
// (objectType, objectID, relation). The caller must hold s.mu.
func (s *MemoryStore) directHoldersLocked(objectType, objectID, relation string) int {
	orKey := objectRelationKey(objectType, objectID, relation)
	tuples, ok := s.byObjectRelation[orKey]
	if !ok {
		return 0
	}
	count := 0
	for _, t := range tuples {
		if t.UserRelation == "" {
			count++
		}
	}
	return count
}

// DeleteIfAbove deletes t only if the object retains more than min direct
// holders of (object, relation). It is atomic under the store's write lock:
// the count and delete happen without releasing s.mu, so concurrent sibling
// deletes cannot both observe the same pre-delete count. Deleting a tuple that
// is not present is not a floor breach and returns nil.
func (s *MemoryStore) DeleteIfAbove(_ context.Context, t model.Tuple, min int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	orKey := objectRelationKey(t.ObjectType, t.ObjectID, t.Relation)
	tk := tupleKey(t)
	tuples, ok := s.byObjectRelation[orKey]
	if !ok {
		return nil
	}
	if _, present := tuples[tk]; !present {
		// Deleting a missing tuple is not a floor breach.
		return nil
	}

	if s.directHoldersLocked(t.ObjectType, t.ObjectID, t.Relation) <= min {
		return model.ErrLastHolder
	}

	s.deleteLocked(t)
	return nil
}

// WriteTx applies all writes then all deletes under one held write lock,
// all-or-nothing. The memory store cannot fail mid-mutation, so a precheck of
// the inputs before any index mutation is sufficient for atomicity; there is no
// snapshot/restore (which would not consistently restore secondary indexes).
func (s *MemoryStore) WriteTx(_ context.Context, writes, deletes []model.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range writes {
		s.writeLocked(t)
	}
	for _, t := range deletes {
		s.deleteLocked(t)
	}
	return nil
}

// ReplaceTx atomically replaces the tuples matching filter under one write
// lock. Holding the lock across delta computation, precommit, and mutation
// gives concurrent replacements exact last-writer semantics.
func (s *MemoryStore) ReplaceTx(
	_ context.Context,
	filter model.TupleFilter,
	replacements []model.Tuple,
	precommit TuplePrecommit,
) ([]model.Tuple, []model.Tuple, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := make([]model.Tuple, 0)
	for _, tuples := range s.byObjectRelation {
		for _, tuple := range tuples {
			if matchesFilter(tuple, filter) {
				current = append(current, tuple)
			}
		}
	}
	writes, deletes := ReplacementDiff(current, replacements)
	if precommit != nil {
		if err := precommit(writes, deletes); err != nil {
			return nil, nil, err
		}
	}
	for _, tuple := range writes {
		s.writeLocked(tuple)
	}
	for _, tuple := range deletes {
		s.deleteLocked(tuple)
	}
	return writes, deletes, nil
}

func (s *MemoryStore) Read(_ context.Context, filter model.TupleFilter) ([]model.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Fast path: if we have object+relation, use index.
	var result []model.Tuple
	if filter.ObjectType != "" && filter.ObjectID != "" && filter.Relation != "" {
		orKey := objectRelationKey(filter.ObjectType, filter.ObjectID, filter.Relation)
		tuples, ok := s.byObjectRelation[orKey]
		if ok {
			result = filterTuples(tuples, filter)
		}
	} else {
		// Slow path: scan all tuples.
		for _, tuples := range s.byObjectRelation {
			for _, t := range tuples {
				if matchesFilter(t, filter) {
					result = append(result, t)
				}
			}
		}
	}

	// Merge materialized tuples.
	for _, mtuples := range s.materialized {
		for _, t := range mtuples {
			if matchesFilter(t, filter) {
				result = append(result, t)
			}
		}
	}

	return result, nil
}

func (s *MemoryStore) ReadUsersets(_ context.Context, objectType, objectID, relation string) ([]model.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []model.Tuple

	orKey := objectRelationKey(objectType, objectID, relation)
	if tuples, ok := s.byObjectRelation[orKey]; ok {
		for _, t := range tuples {
			if t.UserRelation != "" {
				result = append(result, t)
			}
		}
	}

	// Merge materialized userset tuples.
	for _, mtuples := range s.materialized {
		for _, t := range mtuples {
			if t.ObjectType == objectType && t.ObjectID == objectID && t.Relation == relation && t.UserRelation != "" {
				result = append(result, t)
			}
		}
	}

	return result, nil
}

// WriteMaterialized atomically replaces all tuples for the named materializer.
// These tuples are merged into Read/ReadUsersets results but are not part of
// the primary index — they live in SDK memory only.
func (s *MemoryStore) WriteMaterialized(name string, tuples []model.Tuple) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.materialized == nil {
		s.materialized = make(map[string][]model.Tuple)
	}
	s.materialized[name] = tuples
}

// ClearMaterialized removes all tuples for the named materializer.
func (s *MemoryStore) ClearMaterialized(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.materialized, name)
}

func filterTuples(tuples map[string]model.Tuple, filter model.TupleFilter) []model.Tuple {
	var result []model.Tuple
	for _, t := range tuples {
		if matchesFilter(t, filter) {
			result = append(result, t)
		}
	}
	return result
}

func matchesFilter(t model.Tuple, f model.TupleFilter) bool {
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

// ReplacementDiff returns the tuples that must be written and deleted to
// transform current into replacements. Results are sorted by tuple key so
// precommit audit ordering is deterministic.
func ReplacementDiff(current, replacements []model.Tuple) (writes, deletes []model.Tuple) {
	currentSet := make(map[string]model.Tuple, len(current))
	for _, tuple := range current {
		currentSet[tupleKey(tuple)] = tuple
	}
	replacementSet := make(map[string]model.Tuple, len(replacements))
	for _, tuple := range replacements {
		replacementSet[tupleKey(tuple)] = tuple
	}
	for key, tuple := range replacementSet {
		if _, exists := currentSet[key]; !exists {
			writes = append(writes, tuple)
		}
	}
	for key, tuple := range currentSet {
		if _, exists := replacementSet[key]; !exists {
			deletes = append(deletes, tuple)
		}
	}
	sort.Slice(writes, func(i, j int) bool { return tupleKey(writes[i]) < tupleKey(writes[j]) })
	sort.Slice(deletes, func(i, j int) bool { return tupleKey(deletes[i]) < tupleKey(deletes[j]) })
	return writes, deletes
}

// CountByObjectType returns the number of tuples grouped by object type.
func (s *MemoryStore) CountByObjectType(_ context.Context) (map[string]int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[string]int64)
	for _, tuples := range s.byObjectRelation {
		for _, t := range tuples {
			counts[t.ObjectType]++
		}
	}
	return counts, nil
}
