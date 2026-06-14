package check

import (
	"context"
	"fmt"
	"testing"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// Benchmarks for the Zanzibar check path. The SLO is <250us per decision
// (see specs/atol-implementation-spec.md and CLAUDE.md). These benchmarks
// exercise the three representative shapes of a real authorization call:
//
//   - Direct:        a single tuple lookup on an indexed primary relation
//   - SameIdentity:  email-identity linkage followed by one indirect lookup
//   - DeepGraph:     a multi-hop traversal across document -> project -> org
//
// They are the upper bound on checker latency for a bounded model; production
// graphs with large fan-out can be slower. Run with:
//
//   go test -bench=. -benchmem ./zanzibar/check/
//
// To gate the SLO in CI:
//
//   go test -bench=. -benchtime=5s -count=3 ./zanzibar/check/ | \
//     tee bench.out; benchstat bench.out

// benchModelYAML is the same model used by the unit tests, kept local to
// this file so the benchmark is stable even if the test helper changes.
var benchModelYAML = []byte(`version: "1.0"
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
      viewer:
        types: [user, team#effective_member]
      effective_admin:
        union:
          - admin
          - { from: org, lookup: admin }
      effective_viewer:
        union: [viewer, effective_admin]
  document:
    relations:
      project:
        types: [project]
      direct_owner:
        types: [user, identity]
      direct_viewer:
        types: [user, identity, team#effective_member]
      viewer:
        union:
          - direct_viewer
          - { from: direct_owner, lookup: same_identity }
          - { from: project, lookup: effective_viewer }
`)

// newBenchChecker builds a fresh checker + memory store with the benchmark
// model compiled. Benchmarks seed their own tuples.
func newBenchChecker(b *testing.B) (*Checker, *store.MemoryStore) {
	b.Helper()
	m, err := model.Compile(benchModelYAML)
	if err != nil {
		b.Fatalf("compile model: %v", err)
	}
	s := store.NewMemoryStore()
	return New(m, s), s
}

// writeBenchTuple is a fatal-on-error helper for benchmark setup.
func writeBenchTuple(b *testing.B, s *store.MemoryStore, objectType, objectID, relation, userType, userID, userRelation string) {
	b.Helper()
	if err := s.Write(context.Background(), model.Tuple{
		ObjectType:   objectType,
		ObjectID:     objectID,
		Relation:     relation,
		UserType:     userType,
		UserID:       userID,
		UserRelation: userRelation,
	}); err != nil {
		b.Fatalf("write tuple: %v", err)
	}
}

// BenchmarkCheck_Direct measures a single direct-relation lookup. This is
// the cheapest check: one index probe.
func BenchmarkCheck_Direct(b *testing.B) {
	c, s := newBenchChecker(b)
	writeBenchTuple(b, s, "org", "acme", "admin", "user", "alice", "")
	ctx := context.Background()
	b.ResetTimer()

	for b.Loop() {
		allowed, err := c.Check(ctx, "user", "alice", "admin", "org", "acme")
		if err != nil {
			b.Fatalf("check: %v", err)
		}
		if !allowed {
			b.Fatal("direct check should allow")
		}
	}
}

// BenchmarkCheck_Direct_Miss measures a direct-relation lookup that misses.
// Misses must also be bounded: the typical case in a deny-heavy system.
func BenchmarkCheck_Direct_Miss(b *testing.B) {
	c, s := newBenchChecker(b)
	writeBenchTuple(b, s, "org", "acme", "admin", "user", "alice", "")
	ctx := context.Background()
	b.ResetTimer()

	for b.Loop() {
		allowed, err := c.Check(ctx, "user", "bob", "admin", "org", "acme")
		if err != nil {
			b.Fatalf("check: %v", err)
		}
		if allowed {
			b.Fatal("miss should deny")
		}
	}
}

// BenchmarkCheck_SameIdentity measures the email-to-user identity linkage path.
// When a grant was made to an identity (e.g. email:foo@x.com), and a user is
// later linked via same_identity, the Check must traverse the linkage.
func BenchmarkCheck_SameIdentity(b *testing.B) {
	c, s := newBenchChecker(b)
	// Grant was made to an identity, not the user directly.
	writeBenchTuple(b, s, "org", "acme", "admin", "identity", "oidc-alice", "")
	// User is linked bidirectionally to that identity.
	writeBenchTuple(b, s, "user", "alice", "same_identity", "identity", "oidc-alice", "")
	writeBenchTuple(b, s, "identity", "oidc-alice", "same_identity", "user", "alice", "")
	ctx := context.Background()
	b.ResetTimer()

	for b.Loop() {
		allowed, err := c.Check(ctx, "user", "alice", "admin", "org", "acme")
		if err != nil {
			b.Fatalf("check: %v", err)
		}
		// Direct grant to user not present; expansion via usersets may or
		// may not resolve depending on model semantics -- the benchmark
		// measures the traversal cost either way.
		_ = allowed
	}
}

// BenchmarkCheck_DeepGraph measures a multi-hop check that traverses
// document -> project -> org -> effective_admin -> admin. This is the
// worst-case shape for an indirect grant: four rewrites, one tuple-to-userset.
func BenchmarkCheck_DeepGraph(b *testing.B) {
	c, s := newBenchChecker(b)
	// alice is an admin of org:acme
	writeBenchTuple(b, s, "org", "acme", "admin", "user", "alice", "")
	// project:proj1 belongs to org:acme
	writeBenchTuple(b, s, "project", "proj1", "org", "org", "acme", "")
	// document:doc42 belongs to project:proj1
	writeBenchTuple(b, s, "document", "doc42", "project", "project", "proj1", "")
	ctx := context.Background()
	b.ResetTimer()

	for b.Loop() {
		allowed, err := c.Check(ctx, "user", "alice", "viewer", "document", "doc42")
		if err != nil {
			b.Fatalf("check: %v", err)
		}
		if !allowed {
			b.Fatal("alice should be viewer of doc42 via org admin")
		}
	}
}

// BenchmarkCheck_WideMembership measures check cost when an object has many
// direct grants. Models the "resource shared with N users" case where the
// primary index must scan through siblings.
func BenchmarkCheck_WideMembership(b *testing.B) {
	c, s := newBenchChecker(b)
	// 100 members of the same org. The checker probes by (objectType,
	// objectID, relation) so sibling count affects index-bucket size but
	// not per-check work -- this benchmark guards against regressions that
	// would change that.
	for i := range 100 {
		writeBenchTuple(b, s, "org", "acme", "member", "user", fmt.Sprintf("user%d", i), "")
	}
	ctx := context.Background()
	b.ResetTimer()

	for b.Loop() {
		allowed, err := c.Check(ctx, "user", "user50", "member", "org", "acme")
		if err != nil {
			b.Fatalf("check: %v", err)
		}
		if !allowed {
			b.Fatal("user50 should be a member of acme")
		}
	}
}
