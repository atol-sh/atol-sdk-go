// Package model defines the Zanzibar authorization model types and YAML compiler.
package model

// Model represents a compiled Zanzibar authorization model.
type Model struct {
	Version string
	Types   map[string]*TypeDef
}

// TypeDef defines a type in the authorization model.
type TypeDef struct {
	Name      string
	Relations map[string]*RelationDef
}

// RelationDef defines a relation on a type.
type RelationDef struct {
	Name string
	// DirectTypes lists the types that can be directly assigned to this relation.
	// Each entry is "type" or "type#relation" for userset references.
	DirectTypes []string
	// Rewrites defines how this relation is computed.
	Rewrites []RewriteRule
}

// RewriteRule defines how a relation is computed.
// Exactly one of Direct, Union, or FromLookup is set.
type RewriteRule struct {
	// Direct means this relation accepts direct tuple assignments.
	Direct bool
	// ComputedRelation references another relation on the same type (computed_userset).
	ComputedRelation string
	// FromLookup follows the From relation to find objects, then checks Lookup on each (tuple_to_userset).
	FromLookup *FromLookup
}

// FromLookup represents a tuple-to-userset rewrite.
// "Follow the 'From' relation on the current object, then check 'Lookup' on each target."
type FromLookup struct {
	From   string
	Lookup string
}

// Tuple represents a single relationship tuple in Zanzibar format:
// object_type:object_id#relation@user_type:user_id[#user_relation]
type Tuple struct {
	ObjectType   string
	ObjectID     string
	Relation     string
	UserType     string
	UserID       string
	UserRelation string // empty for direct, e.g. "effective_member" for userset
}

// TupleFilter specifies criteria for reading tuples.
// Empty fields match any value.
type TupleFilter struct {
	ObjectType   string
	ObjectID     string
	Relation     string
	UserType     string
	UserID       string
	UserRelation string
}

// UserKey returns the full user key in "type:id" or "type:id#relation" format.
func (t Tuple) UserKey() string {
	key := t.UserType + ":" + t.UserID
	if t.UserRelation != "" {
		key += "#" + t.UserRelation
	}
	return key
}

// ObjectKey returns the full object key in "type:id" format.
func (t Tuple) ObjectKey() string {
	return t.ObjectType + ":" + t.ObjectID
}
