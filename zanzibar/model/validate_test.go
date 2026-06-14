package model

import (
	"testing"
)

func TestValidateTuple_NilModel(t *testing.T) {
	err := ValidateTuple(nil, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "alice",
	})
	if err != nil {
		t.Errorf("ValidateTuple(nil model) = %v, want nil", err)
	}
}

func TestValidateTuple_ValidDirect(t *testing.T) {
	m := &Model{
		Types: map[string]*TypeDef{
			"user": {Name: "user"},
			"document": {
				Name: "document",
				Relations: map[string]*RelationDef{
					"editor": {Name: "editor", DirectTypes: []string{"user"}},
				},
			},
		},
	}

	err := ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "user", UserID: "alice",
	})
	if err != nil {
		t.Errorf("ValidateTuple(valid) = %v, want nil", err)
	}
}

func TestValidateTuple_UnknownObjectType(t *testing.T) {
	m := &Model{Types: map[string]*TypeDef{}}

	err := ValidateTuple(m, Tuple{
		ObjectType: "nonexistent", ObjectID: "x", Relation: "r",
		UserType: "user", UserID: "alice",
	})
	if err == nil {
		t.Error("ValidateTuple(unknown type) should error")
	}
}

func TestValidateTuple_UnknownRelation(t *testing.T) {
	m := &Model{
		Types: map[string]*TypeDef{
			"document": {Name: "document", Relations: map[string]*RelationDef{}},
		},
	}

	err := ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "nonexistent",
		UserType: "user", UserID: "alice",
	})
	if err == nil {
		t.Error("ValidateTuple(unknown relation) should error")
	}
}

func TestValidateTuple_DisallowedUserType(t *testing.T) {
	m := &Model{
		Types: map[string]*TypeDef{
			"user": {Name: "user"},
			"document": {
				Name: "document",
				Relations: map[string]*RelationDef{
					"editor": {Name: "editor", DirectTypes: []string{"user"}},
				},
			},
		},
	}

	err := ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
		UserType: "org", UserID: "acme", // org not in DirectTypes
	})
	if err == nil {
		t.Error("ValidateTuple(disallowed user type) should error")
	}
}

func TestValidateTuple_UsersetRelation(t *testing.T) {
	m := &Model{
		Types: map[string]*TypeDef{
			"user": {Name: "user"},
			"org": {
				Name: "org",
				Relations: map[string]*RelationDef{
					"member": {Name: "member", DirectTypes: []string{"user"}},
				},
			},
			"document": {
				Name: "document",
				Relations: map[string]*RelationDef{
					"viewer": {Name: "viewer", DirectTypes: []string{"org#member"}},
				},
			},
		},
	}

	// Valid userset tuple.
	err := ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
		UserType: "org", UserID: "acme", UserRelation: "member",
	})
	if err != nil {
		t.Errorf("ValidateTuple(valid userset) = %v, want nil", err)
	}

	// Invalid: user relation doesn't exist on user type.
	err = ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
		UserType: "org", UserID: "acme", UserRelation: "nonexistent",
	})
	if err == nil {
		t.Error("ValidateTuple(invalid userset relation) should error")
	}

	// Invalid: user type doesn't exist.
	err = ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
		UserType: "ghost", UserID: "x", UserRelation: "member",
	})
	if err == nil {
		t.Error("ValidateTuple(unknown user type with relation) should error")
	}
}

func TestValidateTuple_NoDirectTypes(t *testing.T) {
	m := &Model{
		Types: map[string]*TypeDef{
			"document": {
				Name: "document",
				Relations: map[string]*RelationDef{
					"viewer": {Name: "viewer"}, // no DirectTypes — any user type allowed
				},
			},
		},
	}

	err := ValidateTuple(m, Tuple{
		ObjectType: "document", ObjectID: "doc-1", Relation: "viewer",
		UserType: "anything", UserID: "x",
	})
	if err != nil {
		t.Errorf("ValidateTuple(no direct types) = %v, want nil", err)
	}
}

func TestTuple_UserKey(t *testing.T) {
	tests := []struct {
		tuple Tuple
		want  string
	}{
		{
			tuple: Tuple{UserType: "user", UserID: "alice"},
			want:  "user:alice",
		},
		{
			tuple: Tuple{UserType: "org", UserID: "acme", UserRelation: "member"},
			want:  "org:acme#member",
		},
	}

	for _, tt := range tests {
		got := tt.tuple.UserKey()
		if got != tt.want {
			t.Errorf("UserKey() = %q, want %q", got, tt.want)
		}
	}
}

func TestTuple_ObjectKey(t *testing.T) {
	tuple := Tuple{ObjectType: "document", ObjectID: "doc-1"}
	got := tuple.ObjectKey()
	if got != "document:doc-1" {
		t.Errorf("ObjectKey() = %q, want %q", got, "document:doc-1")
	}
}
