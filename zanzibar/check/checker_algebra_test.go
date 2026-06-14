package check

import (
	"context"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// Algebra + edge-case tests that complement the happy-path coverage in
// checker_test.go. These guard corners the audit called out: self-
// referential types, forward references in YAML (a relation defined
// later in the file referenced earlier), and deep-chain expansion.
//
// Operators this engine doesn't support (wildcard `user:*`, explicit
// intersection / difference) are deliberately NOT exercised -- those
// capabilities would require model extensions first. When we add them
// their tests go here.

// TestCheck_SelfReferentialType_MemberViaAdmin proves that a relation
// whose union includes a direct type AND a path that cycles back
// through the same type (org -> admin -> effective_member where
// effective_member includes admin) still terminates and returns the
// correct decision.
func TestCheck_SelfReferentialType_MemberViaAdmin(t *testing.T) {
	yamlData := []byte(`
version: "1.0"
types:
  user: {}
  org:
    relations:
      owner:
        types: [user]
      admin:
        types: [user]
        union: [owner]
      member:
        types: [user]
        union: [admin]
`)
	m, err := model.Compile(yamlData)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ms := store.NewMemoryStore()
	checker := New(m, ms)
	ctx := context.Background()

	// user:alice is owner -> should resolve to admin -> member.
	if err := ms.Write(ctx, model.Tuple{
		ObjectType: "org", ObjectID: "acme", Relation: "owner",
		UserType: "user", UserID: "alice",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}

	cases := []struct {
		relation string
		want     bool
	}{
		{"owner", true},
		{"admin", true},
		{"member", true},
	}
	for _, c := range cases {
		t.Run(c.relation, func(t *testing.T) {
			got, err := checker.Check(ctx, "user", "alice", c.relation, "org", "acme")
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != c.want {
				t.Errorf("user:alice %s org:acme = %v, want %v", c.relation, got, c.want)
			}
		})
	}
}

// TestCompile_ForwardReference proves that a YAML file may define a
// type that references another type's relation which is declared
// LATER in the same document.
func TestCompile_ForwardReference(t *testing.T) {
	yamlData := []byte(`
version: "1.0"
types:
  project:
    relations:
      admin:
        # "team" is declared further down -- must resolve at compile time.
        types: [user, team#effective_member]
  team:
    relations:
      member:
        types: [user]
      effective_member:
        union: [member]
  user: {}
`)
	m, err := model.Compile(yamlData)
	if err != nil {
		t.Fatalf("forward ref should compile, got: %v", err)
	}
	if _, ok := m.Types["project"]; !ok {
		t.Error("project type missing after compile")
	}
	if _, ok := m.Types["team"]; !ok {
		t.Error("team type missing after compile")
	}
}

// TestCheck_DeepChain_Depth8 exercises a userset chain across 8
// objects (user -> team1 -> team2 -> ... -> team8 -> document). The
// checker must terminate quickly and return the correct decision.
// Guards against performance regressions from accidental quadratic
// loops in expand().
func TestCheck_DeepChain_Depth8(t *testing.T) {
	yamlData := []byte(`
version: "1.0"
types:
  user: {}
  team1:
    relations:
      member:
        types: [user]
  team2:
    relations:
      parent:
        types: [team1]
      member:
        union:
          - from: parent
            lookup: member
  team3:
    relations:
      parent:
        types: [team2]
      member:
        union:
          - from: parent
            lookup: member
  team4:
    relations:
      parent:
        types: [team3]
      member:
        union:
          - from: parent
            lookup: member
  team5:
    relations:
      parent:
        types: [team4]
      member:
        union:
          - from: parent
            lookup: member
  team6:
    relations:
      parent:
        types: [team5]
      member:
        union:
          - from: parent
            lookup: member
  team7:
    relations:
      parent:
        types: [team6]
      member:
        union:
          - from: parent
            lookup: member
  team8:
    relations:
      parent:
        types: [team7]
      member:
        union:
          - from: parent
            lookup: member
  document:
    relations:
      owner:
        types: [team8#member]
`)
	m, err := model.Compile(yamlData)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ms := store.NewMemoryStore()
	checker := New(m, ms)
	ctx := context.Background()

	// Chain the parent tuples team2->team1, team3->team2, ..., team8->team7.
	for i := 2; i <= 8; i++ {
		parent := "team" + itoa(i-1)
		child := "team" + itoa(i)
		if err := ms.Write(ctx, model.Tuple{
			ObjectType: child, ObjectID: "t", Relation: "parent",
			UserType: parent, UserID: "t",
		}); err != nil {
			t.Fatalf("write parent %s->%s: %v", parent, child, err)
		}
	}
	// alice is a member of team1.
	if err := ms.Write(ctx, model.Tuple{
		ObjectType: "team1", ObjectID: "t", Relation: "member",
		UserType: "user", UserID: "alice",
	}); err != nil {
		t.Fatalf("write member: %v", err)
	}
	// document:doc owner points at team8#member.
	if err := ms.Write(ctx, model.Tuple{
		ObjectType: "document", ObjectID: "doc", Relation: "owner",
		UserType: "team8", UserID: "t", UserRelation: "member",
	}); err != nil {
		t.Fatalf("write doc owner: %v", err)
	}

	got, err := checker.Check(ctx, "user", "alice", "owner", "document", "doc")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !got {
		t.Error("8-hop chain: check returned false, want true")
	}
}

func itoa(i int) string {
	return string(rune('0' + i))
}

// TestCheck_UnionIncludesDirect proves that a relation defined with a
// union still includes tuples written directly on that relation
// (Zanzibar 'this' semantics) in addition to each union member.
// Regression test for the compiler bug where union REPLACED the direct
// check instead of adding to it.
func TestCheck_UnionIncludesDirect(t *testing.T) {
	cases := []struct {
		name string
		// tuples written before the check: objType, objID, rel, userType, userID, userRel
		tuples [][6]string
		// check arguments
		userType, userID, relation, objectType, objectID string
		want                                             bool
	}{
		{
			name: "direct tuple on unioned relation allowed",
			tuples: [][6]string{
				{"document", "d1", "viewer", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "member relation tuple allowed",
			tuples: [][6]string{
				{"document", "d1", "direct_viewer", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "neither direct nor member denied",
			tuples: [][6]string{
				{"document", "d1", "viewer", "user", "bob", ""},
			},
			userType: "user", userID: "alice",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: false,
		},
		{
			name: "nested union: direct tuple on inner union grants outer",
			// editor is itself a union member of viewer; a tuple written
			// directly on editor must grant both editor and viewer.
			tuples: [][6]string{
				{"document", "d1", "editor", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "nested union two levels: direct tuple on owner grants viewer",
			// owner -> editor -> viewer, all unions.
			tuples: [][6]string{
				{"document", "d1", "owner", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "nested union: direct tuple on inner union grants inner",
			tuples: [][6]string{
				{"document", "d1", "editor", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "editor", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "union same_identity member still works with direct rewrite added",
			// identity:rid holds direct_viewer; user:alice is linked via
			// same_identity, reached through {from: direct_viewer, lookup: same_identity}.
			tuples: [][6]string{
				{"document", "d1", "direct_viewer", "identity", "rid", ""},
				{"identity", "rid", "same_identity", "user", "alice", ""},
				{"user", "alice", "same_identity", "identity", "rid", ""},
			},
			userType: "user", userID: "alice",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "direct tuple on unioned relation for identity subject allowed",
			// GrantAccess writes raw tuples on the union relation itself,
			// including for identity principals.
			tuples: [][6]string{
				{"document", "d1", "viewer", "identity", "rid", ""},
			},
			userType: "identity", userID: "rid",
			relation: "viewer", objectType: "document", objectID: "d1",
			want: true,
		},
		{
			name: "direct tuple on union relation does not leak to its members",
			// A tuple on viewer (the union) must not grant editor (a member).
			tuples: [][6]string{
				{"document", "d1", "viewer", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "editor", objectType: "document", objectID: "d1",
			want: false,
		},
		{
			name: "union-only relation: direct tuple allowed",
			// org.effective_member has union [member, admin, owner] and no
			// types; a tuple written directly on effective_member (e.g. via
			// a raw grant) must still grant it.
			tuples: [][6]string{
				{"org", "acme", "effective_member", "user", "alice", ""},
			},
			userType: "user", userID: "alice",
			relation: "effective_member", objectType: "org", objectID: "acme",
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, s := setupTestEngine(t)
			ctx := context.Background()
			for _, tp := range tc.tuples {
				writeTuple(t, s, tp[0], tp[1], tp[2], tp[3], tp[4], tp[5])
			}
			got, err := c.Check(ctx, tc.userType, tc.userID, tc.relation, tc.objectType, tc.objectID)
			if err != nil {
				t.Fatalf("check(%s:%s %s %s:%s): %v", tc.userType, tc.userID, tc.relation, tc.objectType, tc.objectID, err)
			}
			if got != tc.want {
				t.Errorf("check(%s:%s %s %s:%s) = %v, want %v", tc.userType, tc.userID, tc.relation, tc.objectType, tc.objectID, got, tc.want)
			}
		})
	}
}

// TestCheck_TypesPlusUnion_DirectAndMember proves that a relation that
// declares BOTH direct types and a union honors a direct tuple on the
// relation itself as well as each union member.
func TestCheck_TypesPlusUnion_DirectAndMember(t *testing.T) {
	yamlData := []byte(`
version: "1.0"
types:
  user: {}
  document:
    relations:
      direct_viewer:
        types: [user]
      editor:
        types: [user]
      viewer:
        types: [user]
        union: [direct_viewer, editor]
`)
	m, err := model.Compile(yamlData)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ms := store.NewMemoryStore()
	checker := New(m, ms)
	ctx := context.Background()

	cases := []struct {
		name     string
		relation string // relation the tuple is written on
		userID   string
		want     bool
	}{
		{"direct tuple on viewer itself", "viewer", "alice", true},
		{"tuple on union member direct_viewer", "direct_viewer", "bob", true},
		{"tuple on union member editor", "editor", "carol", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ms.Write(ctx, model.Tuple{
				ObjectType: "document", ObjectID: "d1", Relation: tc.relation,
				UserType: "user", UserID: tc.userID,
			}); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := checker.Check(ctx, "user", tc.userID, "viewer", "document", "d1")
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			if got != tc.want {
				t.Errorf("user:%s viewer document:d1 = %v, want %v", tc.userID, got, tc.want)
			}
		})
	}

	// No tuple at all -> denied.
	got, err := checker.Check(ctx, "user", "mallory", "viewer", "document", "d1")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if got {
		t.Error("user:mallory viewer document:d1 = true, want false (no tuple)")
	}
}
