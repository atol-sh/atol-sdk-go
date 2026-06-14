// Package check implements the Zanzibar graph traversal algorithm
// for Check, ListObjects, and ListUsers operations.
package check

import (
	"context"
	"fmt"
	"strings"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// Checker implements Zanzibar-style graph traversal for relationship checks.
type Checker struct {
	model *model.Model
	store store.TupleStore
}

// New creates a Checker with the given model and tuple store.
func New(m *model.Model, s store.TupleStore) *Checker {
	return &Checker{model: m, store: s}
}

// Check returns true if the user has the given relation on the object.
// Implements Zanzibar section 3.2.3 with cycle detection via a visited set.
func (c *Checker) Check(ctx context.Context, userType, userID, relation, objectType, objectID string) (bool, error) {
	visited := make(map[string]bool)
	return c.check(ctx, userType, userID, "", relation, objectType, objectID, visited)
}

// CheckWithContext creates a temporary Checker that overlays the given context
// tuples on top of this Checker's store for the duration of the check. Context
// tuples are never persisted — they exist only for this evaluation.
func (c *Checker) CheckWithContext(ctx context.Context, contextTuples []model.Tuple, userType, userID, relation, objectType, objectID string) (bool, error) {
	ctxStore := store.NewContextTupleStore(c.store, contextTuples)
	tmp := New(c.model, ctxStore)
	return tmp.Check(ctx, userType, userID, relation, objectType, objectID)
}

func (c *Checker) check(ctx context.Context, userType, userID, userRelation, relation, objectType, objectID string, visited map[string]bool) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// Cycle detection.
	visitKey := fmt.Sprintf("%s:%s#%s@%s:%s#%s", objectType, objectID, relation, userType, userID, userRelation)
	if visited[visitKey] {
		return false, nil
	}
	visited[visitKey] = true

	// Get the relation definition.
	typeDef, ok := c.model.Types[objectType]
	if !ok {
		return false, nil
	}
	relDef, ok := typeDef.Relations[relation]
	if !ok {
		return false, nil
	}

	for _, rw := range relDef.Rewrites {
		if rw.Direct {
			// Step 1: Direct check — is there a tuple (user, relation, object)?
			found, err := c.directCheck(ctx, userType, userID, userRelation, relation, objectType, objectID)
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}

			// Also check userset expansion for direct relations:
			// If there are stored tuples with userset users (type:id#rel),
			// check if the requesting user satisfies the userset.
			found, err = c.usersetExpansion(ctx, userType, userID, relation, objectType, objectID, visited)
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}
		}

		if rw.ComputedRelation != "" {
			// Step 2: Computed userset — check another relation on same object.
			found, err := c.check(ctx, userType, userID, userRelation, rw.ComputedRelation, objectType, objectID, visited)
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}
		}

		if rw.FromLookup != nil {
			// Step 3: Tuple-to-userset — follow 'from' relation to find targets,
			// then check 'lookup' on each target.
			found, err := c.tupleToUserset(ctx, userType, userID, userRelation, rw.FromLookup, objectType, objectID, visited)
			if err != nil {
				return false, err
			}
			if found {
				return true, nil
			}
		}
	}

	return false, nil
}

// directCheck looks for a direct tuple match.
func (c *Checker) directCheck(ctx context.Context, userType, userID, userRelation, relation, objectType, objectID string) (bool, error) {
	tuples, err := c.store.Read(ctx, model.TupleFilter{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	})
	if err != nil {
		return false, fmt.Errorf("direct check: %w", err)
	}
	return len(tuples) > 0, nil
}

// usersetExpansion handles userset references in stored tuples.
// For each tuple (objectType:objectID#relation@someType:someID#someRel),
// check if the requesting user satisfies someType:someID#someRel.
func (c *Checker) usersetExpansion(ctx context.Context, userType, userID, relation, objectType, objectID string, visited map[string]bool) (bool, error) {
	usersets, err := c.store.ReadUsersets(ctx, objectType, objectID, relation)
	if err != nil {
		return false, fmt.Errorf("read usersets: %w", err)
	}

	for _, us := range usersets {
		// Check if the requesting user has the userset relation on the userset object.
		found, err := c.check(ctx, userType, userID, "", us.UserRelation, us.UserType, us.UserID, visited)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}

	return false, nil
}

// tupleToUserset follows the 'from' relation to find target objects,
// then checks the 'lookup' relation on each.
func (c *Checker) tupleToUserset(ctx context.Context, userType, userID, userRelation string, fl *model.FromLookup, objectType, objectID string, visited map[string]bool) (bool, error) {
	// Find all objects linked via the 'from' relation.
	fromTuples, err := c.store.Read(ctx, model.TupleFilter{
		ObjectType: objectType,
		ObjectID:   objectID,
		Relation:   fl.From,
	})
	if err != nil {
		return false, fmt.Errorf("read from relation %q: %w", fl.From, err)
	}

	for _, ft := range fromTuples {
		// The target is the user of the from-tuple.
		targetType := ft.UserType
		targetID := ft.UserID

		// Check the 'lookup' relation on the target.
		found, err := c.check(ctx, userType, userID, userRelation, fl.Lookup, targetType, targetID, visited)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}

	return false, nil
}

// ParseUserKey parses "type:id" or "type:id#relation" into components.
func ParseUserKey(key string) (userType, userID, userRelation string) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return key, "", ""
	}
	userType = parts[0]
	rest := parts[1]

	if idx := strings.Index(rest, "#"); idx >= 0 {
		userID = rest[:idx]
		userRelation = rest[idx+1:]
	} else {
		userID = rest
	}
	return
}

// ParseObjectKey parses "type:id" into components.
func ParseObjectKey(key string) (objectType, objectID string) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return key, ""
	}
	return parts[0], parts[1]
}
