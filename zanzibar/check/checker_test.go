package check

import (
	"context"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

func setupTestEngine(t *testing.T) (*Checker, *store.MemoryStore) {
	t.Helper()

	yamlData := []byte(`
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

	m, err := model.Compile(yamlData)
	if err != nil {
		t.Fatalf("compile model: %v", err)
	}

	s := store.NewMemoryStore()
	c := New(m, s)
	return c, s
}

func writeTuple(t *testing.T, s *store.MemoryStore, objectType, objectID, relation, userType, userID, userRelation string) {
	t.Helper()
	err := s.Write(context.Background(), model.Tuple{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	})
	if err != nil {
		t.Fatalf("write tuple: %v", err)
	}
}

func TestCheck_DirectRelation(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	writeTuple(t, s, "org", "acme", "admin", "user", "alice", "")

	tests := []struct {
		name     string
		userType string
		userID   string
		relation string
		want     bool
	}{
		{"admin has access", "user", "alice", "admin", true},
		{"non-admin denied", "user", "bob", "admin", false},
		{"wrong relation", "user", "alice", "member", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Check(ctx, tt.userType, tt.userID, tt.relation, "org", "acme")
			if err != nil {
				t.Fatalf("check error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Check(%s:%s, %s, org:acme) = %v, want %v", tt.userType, tt.userID, tt.relation, got, tt.want)
			}
		})
	}
}

func TestCheck_UnionResolution(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	writeTuple(t, s, "org", "acme", "member", "user", "alice", "")
	writeTuple(t, s, "org", "acme", "admin", "user", "bob", "")
	writeTuple(t, s, "org", "acme", "owner", "user", "charlie", "")

	// effective_member = union(member, admin, owner)
	tests := []struct {
		name string
		user string
		want bool
	}{
		{"member is effective_member", "alice", true},
		{"admin is effective_member", "bob", true},
		{"owner is effective_member", "charlie", true},
		{"unknown is not effective_member", "dave", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Check(ctx, "user", tt.user, "effective_member", "org", "acme")
			if err != nil {
				t.Fatalf("check error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Check(user:%s, effective_member, org:acme) = %v, want %v", tt.user, got, tt.want)
			}
		})
	}
}

func TestCheck_TupleToUserset(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	// org:acme has admin user:alice
	writeTuple(t, s, "org", "acme", "admin", "user", "alice", "")

	// project:proj1 belongs to org:acme
	writeTuple(t, s, "project", "proj1", "org", "org", "acme", "")

	// project.effective_admin = union(admin, {from: org, lookup: admin})
	// alice is org:acme admin → should be project:proj1 effective_admin

	got, err := c.Check(ctx, "user", "alice", "effective_admin", "project", "proj1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("org admin should be effective_admin of project via tuple-to-userset")
	}

	// bob is not org admin → should not be effective_admin
	got, err = c.Check(ctx, "user", "bob", "effective_admin", "project", "proj1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if got {
		t.Error("non-org-admin should not be effective_admin")
	}
}

func TestCheck_SameIdentity(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	// user:remi has same_identity with identity:oidc://auth/abc
	writeTuple(t, s, "user", "remi", "same_identity", "identity", "oidc://auth/abc", "")
	writeTuple(t, s, "identity", "oidc://auth/abc", "same_identity", "user", "remi", "")

	// document:doc1 has direct_owner identity:oidc://auth/abc
	writeTuple(t, s, "document", "doc1", "direct_owner", "identity", "oidc://auth/abc", "")

	// document.owner = union(direct_owner, {from: direct_owner, lookup: same_identity})
	// identity:oidc://auth/abc is direct_owner → identity has same_identity → user:remi

	// identity should be owner directly
	got, err := c.Check(ctx, "identity", "oidc://auth/abc", "owner", "document", "doc1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("identity should be document owner via direct_owner")
	}

	// user:remi should be owner via same_identity
	got, err = c.Check(ctx, "user", "remi", "owner", "document", "doc1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("user should be document owner via same_identity cross-ref")
	}
}

func TestCheck_CycleDetection(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	// Create bidirectional same_identity (potential cycle)
	writeTuple(t, s, "user", "remi", "same_identity", "identity", "oidc://x", "")
	writeTuple(t, s, "identity", "oidc://x", "same_identity", "user", "remi", "")

	// This should not hang or panic due to cycles
	_, err := c.Check(ctx, "user", "remi", "same_identity", "user", "remi")
	if err != nil {
		t.Fatalf("check error (cycle): %v", err)
	}
}

func TestCheck_UsersetMembership(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	// team:eng has member user:alice
	writeTuple(t, s, "team", "eng", "member", "user", "alice", "")

	// project:proj1 has admin team:eng#effective_member
	writeTuple(t, s, "project", "proj1", "admin", "team", "eng", "effective_member")

	// alice should be project admin because she's team:eng member,
	// which means she's team:eng#effective_member (via union),
	// and project:proj1 admin includes team:eng#effective_member
	got, err := c.Check(ctx, "user", "alice", "admin", "project", "proj1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("team member should have project admin via userset membership")
	}

	// bob is not team member → should not have access
	got, err = c.Check(ctx, "user", "bob", "admin", "project", "proj1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if got {
		t.Error("non-team-member should not have project admin")
	}
}

func TestListObjects(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	writeTuple(t, s, "org", "acme", "admin", "user", "alice", "")
	writeTuple(t, s, "org", "beta", "member", "user", "alice", "")
	writeTuple(t, s, "org", "gamma", "admin", "user", "bob", "")

	// alice is effective_member of acme (admin) and beta (member)
	objects, err := c.ListObjects(ctx, "user", "alice", "effective_member", "org")
	if err != nil {
		t.Fatalf("list objects error: %v", err)
	}

	found := make(map[string]bool)
	for _, o := range objects {
		found[o] = true
	}

	if !found["acme"] {
		t.Error("expected acme in list")
	}
	if !found["beta"] {
		t.Error("expected beta in list")
	}
	if found["gamma"] {
		t.Error("gamma should not be in list for alice")
	}
}

func TestListUsers(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	writeTuple(t, s, "org", "acme", "admin", "user", "alice", "")
	writeTuple(t, s, "org", "acme", "member", "user", "bob", "")

	users, err := c.ListUsers(ctx, "admin", "org", "acme")
	if err != nil {
		t.Fatalf("list users error: %v", err)
	}

	if len(users) != 1 {
		t.Fatalf("expected 1 admin user, got %d", len(users))
	}
	if users[0] != "user:alice" {
		t.Errorf("expected user:alice, got %s", users[0])
	}
}

func TestCheckWithContext_DirectRelation(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	// alice is a stored admin
	writeTuple(t, s, "org", "acme", "admin", "user", "alice", "")

	// bob is granted member via context tuple only
	contextTuples := []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member",
			UserType: "user", UserID: "bob"},
	}

	// bob should be effective_member via context tuple
	got, err := c.CheckWithContext(ctx, contextTuples, "user", "bob", "effective_member", "org", "acme")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("bob should be effective_member via context tuple")
	}

	// alice should still work via stored tuple
	got, err = c.CheckWithContext(ctx, contextTuples, "user", "alice", "effective_member", "org", "acme")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("alice should still be effective_member via stored tuple")
	}

	// charlie has no access via either
	got, err = c.CheckWithContext(ctx, contextTuples, "user", "charlie", "effective_member", "org", "acme")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if got {
		t.Error("charlie should not be effective_member")
	}
}

func TestCheckWithContext_TupleToUserset(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	// alice is org admin (stored)
	writeTuple(t, s, "org", "acme", "admin", "user", "alice", "")

	// project → org relationship provided as context tuple
	contextTuples := []model.Tuple{
		{ObjectType: "project", ObjectID: "proj1", Relation: "org",
			UserType: "org", UserID: "acme"},
	}

	// alice should be effective_admin of proj1 via context tuple-to-userset
	got, err := c.CheckWithContext(ctx, contextTuples, "user", "alice", "effective_admin", "project", "proj1")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("alice should be effective_admin via context tuple-to-userset")
	}
}

func TestCheckWithContext_NoLeakToStored(t *testing.T) {
	c, s := setupTestEngine(t)
	ctx := context.Background()

	contextTuples := []model.Tuple{
		{ObjectType: "org", ObjectID: "acme", Relation: "member",
			UserType: "user", UserID: "temp"},
	}

	// Check with context — should find temp
	got, err := c.CheckWithContext(ctx, contextTuples, "user", "temp", "effective_member", "org", "acme")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !got {
		t.Error("temp should be effective_member via context")
	}

	// Check WITHOUT context — temp should NOT be found
	got, err = c.Check(ctx, "user", "temp", "effective_member", "org", "acme")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if got {
		t.Error("temp should NOT be effective_member without context tuples")
	}

	// Verify nothing leaked to inner store
	tuples, err := s.Read(ctx, model.TupleFilter{ObjectType: "org", ObjectID: "acme", Relation: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tuples) != 0 {
		t.Errorf("context tuple leaked to store: %d tuples", len(tuples))
	}
}

func TestParseUserKey(t *testing.T) {
	tests := []struct {
		input        string
		wantType     string
		wantID       string
		wantRelation string
	}{
		{"user:alice", "user", "alice", ""},
		{"team:eng#effective_member", "team", "eng", "effective_member"},
		{"identity:oidc://auth/abc", "identity", "oidc://auth/abc", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotType, gotID, gotRel := ParseUserKey(tt.input)
			if gotType != tt.wantType || gotID != tt.wantID || gotRel != tt.wantRelation {
				t.Errorf("ParseUserKey(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.input, gotType, gotID, gotRel, tt.wantType, tt.wantID, tt.wantRelation)
			}
		})
	}
}
