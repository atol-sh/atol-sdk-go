package model

import (
	"testing"
)

func TestCompile_ValidModel(t *testing.T) {
	yaml := []byte(`
version: "1.0"

types:
  user:
    relations:
      same_identity:
        types: [identity]

  identity:
    relations:
      same_identity:
        types: [user]

  org:
    relations:
      owner:
        types: [user]
      admin:
        types: [user, identity]
      member:
        types: [user, identity]
      effective_member:
        union: [member, admin, owner]

  team:
    relations:
      org:
        types: [org]
      lead:
        types: [user]
      member:
        types: [user]
      effective_member:
        union: [member, lead]

  project:
    relations:
      org:
        types: [org]
      admin:
        types: [user, team#effective_member]
      member:
        types: [user, team#effective_member]
      viewer:
        types: [user, team#effective_member]
      effective_admin:
        union:
          - admin
          - { from: org, lookup: admin }
      effective_member:
        union: [member, effective_admin]
      effective_viewer:
        union: [viewer, effective_member]

  document:
    relations:
      project:
        types: [project]
      direct_owner:
        types: [user, identity]
      direct_editor:
        types: [user, identity]
      direct_viewer:
        types: [user, identity, team#effective_member]
      owner:
        union:
          - direct_owner
          - { from: direct_owner, lookup: same_identity }
      editor:
        union:
          - direct_editor
          - owner
          - { from: direct_editor, lookup: same_identity }
          - { from: project, lookup: effective_member }
      viewer:
        union:
          - direct_viewer
          - editor
          - { from: direct_viewer, lookup: same_identity }
          - { from: project, lookup: effective_viewer }
`)

	m, err := Compile(yaml)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	if m.Version != "1.0" {
		t.Errorf("version = %q, want %q", m.Version, "1.0")
	}

	if len(m.Types) != 6 {
		t.Errorf("type count = %d, want 6", len(m.Types))
	}

	// Verify org.effective_member has a direct rewrite plus 3 union entries.
	orgType := m.Types["org"]
	if orgType == nil {
		t.Fatal("missing type: org")
	}
	effMember := orgType.Relations["effective_member"]
	if effMember == nil {
		t.Fatal("missing relation: org.effective_member")
	}
	if len(effMember.Rewrites) != 4 {
		t.Errorf("org.effective_member rewrites = %d, want 4 (direct + 3 members)", len(effMember.Rewrites))
	}
	if !effMember.Rewrites[0].Direct {
		t.Error("org.effective_member[0] should be the direct ('this') rewrite")
	}

	// Verify project.effective_admin has from/lookup.
	projectType := m.Types["project"]
	if projectType == nil {
		t.Fatal("missing type: project")
	}
	effAdmin := projectType.Relations["effective_admin"]
	if effAdmin == nil {
		t.Fatal("missing relation: project.effective_admin")
	}
	if len(effAdmin.Rewrites) != 3 {
		t.Fatalf("project.effective_admin rewrites = %d, want 3 (direct + 2 members)", len(effAdmin.Rewrites))
	}
	if !effAdmin.Rewrites[0].Direct {
		t.Error("project.effective_admin[0] should be the direct ('this') rewrite")
	}
	if effAdmin.Rewrites[2].FromLookup == nil {
		t.Error("project.effective_admin[2] should be from/lookup")
	} else {
		if effAdmin.Rewrites[2].FromLookup.From != "org" {
			t.Errorf("from = %q, want %q", effAdmin.Rewrites[2].FromLookup.From, "org")
		}
		if effAdmin.Rewrites[2].FromLookup.Lookup != "admin" {
			t.Errorf("lookup = %q, want %q", effAdmin.Rewrites[2].FromLookup.Lookup, "admin")
		}
	}

	// Verify typed relation: project.admin allows team#effective_member.
	projAdmin := projectType.Relations["admin"]
	if projAdmin == nil {
		t.Fatal("missing relation: project.admin")
	}
	found := false
	for _, dt := range projAdmin.DirectTypes {
		if dt == "team#effective_member" {
			found = true
		}
	}
	if !found {
		t.Error("project.admin should allow team#effective_member")
	}
}

func TestCompile_MissingType(t *testing.T) {
	yaml := []byte(`
version: "1.0"
types:
  user:
    relations:
      member_of:
        types: [nonexistent]
`)
	_, err := Compile(yaml)
	if err == nil {
		t.Error("expected error for missing type reference")
	}
}

func TestCompile_InvalidRelationRef(t *testing.T) {
	yaml := []byte(`
version: "1.0"
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
  org:
    relations:
      admin:
        types: [user]
      effective:
        union: [nonexistent_relation]
`)
	_, err := Compile(yaml)
	if err == nil {
		t.Error("expected error for invalid computed relation reference")
	}
}

func TestCompile_InvalidTypeRelationRef(t *testing.T) {
	yaml := []byte(`
version: "1.0"
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
  project:
    relations:
      admin:
        types: [user#nonexistent]
`)
	_, err := Compile(yaml)
	if err == nil {
		t.Error("expected error for invalid type#relation reference")
	}
}

func TestCompile_RequiredRelation(t *testing.T) {
	yaml := []byte(`
version: "1.0"
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
  org:
    relations:
      owner:
        types: [user]
        required: true
      member:
        types: [user]
`)
	m, err := Compile(yaml)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	owner := m.Types["org"].Relations["owner"]
	if owner == nil {
		t.Fatal("missing relation: org.owner")
	}
	if got, want := owner.MinHolders, 1; got != want {
		t.Errorf("org.owner MinHolders = %d, want %d", got, want)
	}

	// A relation without `required` must keep the default floor of 0.
	member := m.Types["org"].Relations["member"]
	if member == nil {
		t.Fatal("missing relation: org.member")
	}
	if got, want := member.MinHolders, 0; got != want {
		t.Errorf("org.member MinHolders = %d, want %d", got, want)
	}
}

func TestCompile_RequiredOnUnionRejected(t *testing.T) {
	yaml := []byte(`
version: "1.0"
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
  org:
    relations:
      admin:
        types: [user]
      member:
        types: [user]
      effective_member:
        union: [member, admin]
        required: true
`)
	_, err := Compile(yaml)
	if err == nil {
		t.Error("expected error for `required` on a union relation, got nil")
	}
}

func TestCompile_RequiredOnComputedRejected(t *testing.T) {
	// A single computed_userset entry (no direct types) is not pure-direct.
	yaml := []byte(`
version: "1.0"
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
  org:
    relations:
      admin:
        types: [user]
      effective_admin:
        union: [admin]
        required: true
`)
	_, err := Compile(yaml)
	if err == nil {
		t.Error("expected error for `required` on a computed relation, got nil")
	}
}

func TestCompile_DefaultVersion(t *testing.T) {
	yaml := []byte(`
types:
  user:
    relations:
      same_identity:
        types: [identity]
  identity:
    relations:
      same_identity:
        types: [user]
`)
	m, err := Compile(yaml)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if m.Version != "1.0" {
		t.Errorf("version = %q, want %q", m.Version, "1.0")
	}
}
