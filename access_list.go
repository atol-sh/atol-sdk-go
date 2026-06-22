package sdk

import (
	"context"
	"fmt"

	"atol.sh/sdk-go/zanzibar/check"
	"atol.sh/sdk-go/zanzibar/model"
)

// Relationship is a single authorization tuple in SDK-level value form,
// keeping internal zanzibar/model types off the public boundary.
type Relationship struct {
	// Subject is a user key: "user:remi", "identity:oidc://...", or a
	// userset reference like "group:eng#member".
	Subject string
	// Relation is the relation name, e.g. "admin", "editor", "viewer".
	Relation string
	// Object is an object key in "type:id" form, e.g. "tenant:01H...".
	Object string
}

// RelationshipFilter selects tuples for ReadRelationships. Empty fields match
// any value.
type RelationshipFilter struct {
	// Object is "type:id"; a type-only value ("document:") matches all objects
	// of that type.
	Object string
	// Relation matches the relation name.
	Relation string
	// Subject is "type:id" or "type:id#relation".
	Subject string
}

// Member is a (subject, relation) pair on an object, as returned by ListMembers.
type Member struct {
	Subject  string
	Relation string
}

// ListSubjects returns the user keys that hold relation on object, read from
// the in-process mirror that Can/Check already serve.
//
// It resolves direct tuples and computed-relation unions only; it does NOT
// follow from..lookup rewrites, so same_identity / pending email grants are
// NOT reflected, and userset subjects (e.g. "group:eng#member") are returned
// VERBATIM, not expanded into their members. For an authoritative
// single-subject decision use Can or Check -- never treat this as an
// allow-list.
func (a *Atol) ListSubjects(ctx context.Context, relation, object string) ([]string, error) {
	subjects, err := a.zanzibar.ListUsers(ctx, relation, object)
	if err != nil {
		return nil, fmt.Errorf("list subjects of %s (relation %s): %w", object, relation, err)
	}
	return subjects, nil
}

// ListObjects returns the IDs of objectType that subject has relation on. It
// runs a full Check per candidate, so it DOES honor from..lookup unions. There
// is no pagination or limit -- not for hot request paths on large object types.
func (a *Atol) ListObjects(ctx context.Context, subject, relation, objectType string) ([]string, error) {
	objects, err := a.zanzibar.ListObjects(ctx, subject, relation, objectType)
	if err != nil {
		return nil, fmt.Errorf("list objects of type %s (subject %s, relation %s): %w", objectType, subject, relation, err)
	}
	return objects, nil
}

// ReadRelationships returns the raw tuples matching filter -- a structural dump
// with no rewrite resolution. Use Can/Check for effective access.
//
// It operates on the default model. ReadTuples reads the store directly and has
// no model gate, so this method fails loud with "no model loaded" when no model
// is present rather than returning an empty success.
func (a *Atol) ReadRelationships(ctx context.Context, filter RelationshipFilter) ([]Relationship, error) {
	if a.zanzibar.GetModel() == nil {
		return nil, fmt.Errorf("read relationships: no model loaded")
	}

	var tf model.TupleFilter
	if filter.Subject != "" {
		tf.UserType, tf.UserID, tf.UserRelation = check.ParseUserKey(filter.Subject)
	}
	if filter.Object != "" {
		tf.ObjectType, tf.ObjectID = parseObject(filter.Object)
	}
	tf.Relation = filter.Relation

	tuples, err := a.zanzibar.ReadTuples(ctx, tf)
	if err != nil {
		return nil, fmt.Errorf("read relationships: %w", err)
	}

	out := make([]Relationship, 0, len(tuples))
	for _, t := range tuples {
		out = append(out, Relationship{
			Subject:  t.UserKey(),
			Relation: t.Relation,
			Object:   t.ObjectKey(),
		})
	}
	return out, nil
}

// ListMembers returns every (subject, relation) pair on object across all
// relations declared for the object's type in the DEFAULT model. Like
// ListSubjects it does NOT resolve from..lookup, and role precedence is the
// caller's policy, not the SDK's.
//
// A nil default model is a fail-loud "no model loaded" error. The first
// per-relation error is returned wrapped with context -- members are never
// reported best-effort.
func (a *Atol) ListMembers(ctx context.Context, object string) ([]Member, error) {
	m := a.zanzibar.GetModel()
	if m == nil {
		return nil, fmt.Errorf("list members of %s: no model loaded", object)
	}

	objectType, _ := parseObject(object)
	typeDef, ok := m.Types[objectType]
	if !ok {
		return nil, fmt.Errorf("list members of %s: type %q not in default model", object, objectType)
	}

	var members []Member
	for relation := range typeDef.Relations {
		subjects, err := a.ListSubjects(ctx, relation, object)
		if err != nil {
			return nil, fmt.Errorf("list members of %s (relation %s): %w", object, relation, err)
		}
		for _, s := range subjects {
			members = append(members, Member{Subject: s, Relation: relation})
		}
	}
	return members, nil
}
