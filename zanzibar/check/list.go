package check

import (
	"context"

	"atol.sh/sdk-go/zanzibar/model"
)

// ListObjects returns all object IDs of the given type that the user
// has the specified relation on. Bounded result set.
func (c *Checker) ListObjects(ctx context.Context, userType, userID, relation, objectType string) ([]string, error) {
	// Read all tuples for this object type and relation, then check each.
	// For small-to-medium datasets this is efficient enough.
	// The in-memory store makes this sub-millisecond.
	var result []string
	seen := make(map[string]bool)

	// Scan all tuples that could match.
	allTuples, err := c.store.Read(ctx, model.TupleFilter{
		ObjectType: objectType,
	})
	if err != nil {
		return nil, err
	}

	// Collect unique object IDs.
	candidates := make(map[string]bool)
	for _, t := range allTuples {
		candidates[t.ObjectID] = true
	}

	// Check each candidate.
	for objectID := range candidates {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if seen[objectID] {
			continue
		}
		allowed, err := c.Check(ctx, userType, userID, relation, objectType, objectID)
		if err != nil {
			return nil, err
		}
		if allowed {
			result = append(result, objectID)
			seen[objectID] = true
		}
	}

	return result, nil
}

// ListUsers returns all user keys that have the specified relation
// on the given object. Bounded result set.
func (c *Checker) ListUsers(ctx context.Context, relation, objectType, objectID string) ([]string, error) {
	var result []string
	seen := make(map[string]bool)

	// Read direct tuples for this relation.
	tuples, err := c.store.Read(ctx, model.TupleFilter{
		ObjectType: objectType,
		ObjectID:   objectID,
		Relation:   relation,
	})
	if err != nil {
		return nil, err
	}

	for _, t := range tuples {
		key := t.UserKey()
		if !seen[key] {
			result = append(result, key)
			seen[key] = true
		}
	}

	// Also check computed relations (unions) to find additional users.
	typeDef, ok := c.model.Types[objectType]
	if !ok {
		return result, nil
	}
	relDef, ok := typeDef.Relations[relation]
	if !ok {
		return result, nil
	}

	for _, rw := range relDef.Rewrites {
		if rw.ComputedRelation != "" {
			computed, err := c.ListUsers(ctx, rw.ComputedRelation, objectType, objectID)
			if err != nil {
				return nil, err
			}
			for _, u := range computed {
				if !seen[u] {
					result = append(result, u)
					seen[u] = true
				}
			}
		}
	}

	return result, nil
}
