package sdk_test

import (
	"context"
	"sort"
	"testing"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
)

// enumModel exercises every enumeration path: direct + computed-relation
// unions (viewer = owner|editor), a from..lookup rewrite (document.can_read
// follows document.org then checks org.member), and userset subjects.
var enumModel = []byte(`
types:
  user: {}
  group:
    relations:
      member:
        types: [user]
  org:
    relations:
      member:
        types: [user]
  document:
    relations:
      org:
        types: [org]
      owner:
        types: [user]
      editor:
        types: [user, group#member]
      viewer:
        union: [owner, editor]
      can_read:
        union:
          - from: org
            lookup: member
`)

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := sortedStrings(a), sortedStrings(b)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// TestListSubjects_DirectAndUnionNotFromLookup verifies ListSubjects returns
// direct grantees and computed-relation union grantees, but never a subject
// that is only reachable via a from..lookup (same_identity-style) rewrite.
func TestListSubjects_DirectAndUnionNotFromLookup(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(enumModel))
	// Direct viewer, plus owner and editor that union into viewer.
	engine.Grant("user:vince", "viewer", "document:doc-1")
	engine.Grant("user:olivia", "owner", "document:doc-1")
	engine.Grant("user:ed", "editor", "document:doc-1")
	// A from..lookup-only reachable subject: member of the doc's org. This
	// holds can_read on the document via from..lookup but is NOT a viewer
	// subject and must not appear in ListSubjects(viewer). The doc's org
	// relation points at org:acme (object=document, user=org).
	engine.Grant("org:acme", "org", "document:doc-1")
	engine.Grant("user:morgan", "member", "org:acme")

	got, err := engine.ListSubjects(context.Background(), "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("ListSubjects() error: %v", err)
	}

	want := []string{"user:vince", "user:olivia", "user:ed"}
	if !equalStringSets(got, want) {
		t.Errorf("ListSubjects(viewer) = %v, want %v (direct+union only)", sortedStrings(got), sortedStrings(want))
	}
	for _, s := range got {
		if s == "user:morgan" {
			t.Error("ListSubjects(viewer) included user:morgan, a from..lookup-derived subject")
		}
	}
}

// TestListObjects_HonorsFromLookup verifies ListObjects runs a full Check per
// candidate and so DOES include an object reachable only via from..lookup.
func TestListObjects_HonorsFromLookup(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(enumModel))
	// document:doc-1 belongs to org:acme (object=document, user=org).
	engine.Grant("org:acme", "org", "document:doc-1")
	engine.Grant("user:morgan", "member", "org:acme")

	// Sanity: morgan has no direct can_read tuple, only via from..lookup.
	got, err := engine.ListObjects(context.Background(), "user:morgan", "can_read", "document")
	if err != nil {
		t.Fatalf("ListObjects() error: %v", err)
	}
	if !equalStringSets(got, []string{"doc-1"}) {
		t.Errorf("ListObjects(can_read) = %v, want [doc-1] (from..lookup honored)", sortedStrings(got))
	}
}

// TestReadRelationships_FilterRoundTrip verifies filter translation round-trips
// through ParseUserKey/parseObject, including a userset (#relation) subject.
func TestReadRelationships_FilterRoundTrip(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(enumModel))
	engine.Grant("user:ed", "editor", "document:doc-1")
	engine.Grant("group:eng#member", "editor", "document:doc-1")
	engine.Grant("user:ed", "editor", "document:doc-2")

	tests := []struct {
		name   string
		filter sdk.RelationshipFilter
		want   []sdk.Relationship
	}{
		{
			name:   "by object and relation",
			filter: sdk.RelationshipFilter{Object: "document:doc-1", Relation: "editor"},
			want: []sdk.Relationship{
				{Subject: "user:ed", Relation: "editor", Object: "document:doc-1"},
				{Subject: "group:eng#member", Relation: "editor", Object: "document:doc-1"},
			},
		},
		{
			name:   "by userset subject",
			filter: sdk.RelationshipFilter{Subject: "group:eng#member"},
			want: []sdk.Relationship{
				{Subject: "group:eng#member", Relation: "editor", Object: "document:doc-1"},
			},
		},
		{
			name:   "by plain subject across objects",
			filter: sdk.RelationshipFilter{Subject: "user:ed"},
			want: []sdk.Relationship{
				{Subject: "user:ed", Relation: "editor", Object: "document:doc-1"},
				{Subject: "user:ed", Relation: "editor", Object: "document:doc-2"},
			},
		},
		{
			name:   "match-any empty filter",
			filter: sdk.RelationshipFilter{},
			want: []sdk.Relationship{
				{Subject: "user:ed", Relation: "editor", Object: "document:doc-1"},
				{Subject: "group:eng#member", Relation: "editor", Object: "document:doc-1"},
				{Subject: "user:ed", Relation: "editor", Object: "document:doc-2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.ReadRelationships(context.Background(), tt.filter)
			if err != nil {
				t.Fatalf("ReadRelationships() error: %v", err)
			}
			if !equalRelationshipSets(got, tt.want) {
				t.Errorf("ReadRelationships(%+v) = %v, want %v", tt.filter, got, tt.want)
			}
		})
	}
}

func equalRelationshipSets(a, b []sdk.Relationship) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(r sdk.Relationship) string { return r.Subject + "|" + r.Relation + "|" + r.Object }
	seen := make(map[string]int, len(a))
	for _, r := range a {
		seen[key(r)]++
	}
	for _, r := range b {
		seen[key(r)]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestListMembers_FlattensMultiRelation verifies ListMembers flattens every
// (subject, relation) pair across all relations declared for the object's type.
func TestListMembers_FlattensMultiRelation(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(enumModel))
	engine.Grant("user:olivia", "owner", "document:doc-1")
	engine.Grant("user:ed", "editor", "document:doc-1")
	engine.Grant("user:vince", "viewer", "document:doc-1")
	engine.Grant("org:acme", "org", "document:doc-1")

	got, err := engine.ListMembers(context.Background(), "document:doc-1")
	if err != nil {
		t.Fatalf("ListMembers() error: %v", err)
	}

	want := []sdk.Member{
		{Subject: "user:olivia", Relation: "owner"},
		{Subject: "user:ed", Relation: "editor"},
		// viewer = union(owner, editor) plus the direct viewer grant, so
		// olivia, ed, and vince all hold viewer.
		{Subject: "user:olivia", Relation: "viewer"},
		{Subject: "user:ed", Relation: "viewer"},
		{Subject: "user:vince", Relation: "viewer"},
		{Subject: "org:acme", Relation: "org"},
	}
	if !equalMemberSets(got, want) {
		t.Errorf("ListMembers() = %v,\n want %v", got, want)
	}
}

func equalMemberSets(a, b []sdk.Member) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(m sdk.Member) string { return m.Subject + "|" + m.Relation }
	seen := make(map[string]int, len(a))
	for _, m := range a {
		seen[key(m)]++
	}
	for _, m := range b {
		seen[key(m)]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestEnumeration_NoModelLoaded verifies every enumeration method fails loud
// when no model is loaded, never an empty success.
func TestEnumeration_NoModelLoaded(t *testing.T) {
	engine, err := sdk.New(sdk.Config{}, sdk.WithLocalOnly())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	if _, err := engine.ListSubjects(ctx, "viewer", "document:doc-1"); err == nil {
		t.Error("ListSubjects() with no model: error = nil, want non-nil")
	}
	if _, err := engine.ListObjects(ctx, "user:morgan", "can_read", "document"); err == nil {
		t.Error("ListObjects() with no model: error = nil, want non-nil")
	}
	if _, err := engine.ReadRelationships(ctx, sdk.RelationshipFilter{Object: "document:doc-1"}); err == nil {
		t.Error("ReadRelationships() with no model: error = nil, want non-nil")
	}
	if _, err := engine.ListMembers(ctx, "document:doc-1"); err == nil {
		t.Error("ListMembers() with no model: error = nil, want non-nil")
	}
}
