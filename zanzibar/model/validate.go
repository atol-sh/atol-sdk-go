package model

import "fmt"

// ValidateTuple validates a tuple against the compiled model.
// Returns nil if no model is set or the tuple is valid.
func ValidateTuple(m *Model, t Tuple) error {
	if m == nil {
		return nil
	}

	objType, ok := m.Types[t.ObjectType]
	if !ok {
		return fmt.Errorf("unknown object type %q", t.ObjectType)
	}

	rel, ok := objType.Relations[t.Relation]
	if !ok {
		return fmt.Errorf("relation %q does not exist on type %q", t.Relation, t.ObjectType)
	}

	userRef := t.UserType
	if t.UserRelation != "" {
		userRef = t.UserType + "#" + t.UserRelation
	}

	if len(rel.DirectTypes) > 0 {
		allowed := false
		for _, dt := range rel.DirectTypes {
			if dt == userRef || dt == t.UserType {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("user type %q is not allowed for relation %q on type %q",
				userRef, t.Relation, t.ObjectType)
		}
	}

	if t.UserRelation != "" {
		userType, ok := m.Types[t.UserType]
		if !ok {
			return fmt.Errorf("unknown user type %q", t.UserType)
		}
		if _, ok := userType.Relations[t.UserRelation]; !ok {
			return fmt.Errorf("relation %q does not exist on user type %q", t.UserRelation, t.UserType)
		}
	}

	return nil
}
