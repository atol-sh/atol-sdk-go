package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// jwksServer serves a swappable JWKS and counts fetches.
type jwksServer struct {
	mu      sync.Mutex
	keySet  jose.JSONWebKeySet
	fetches atomic.Int64
}

func (s *jwksServer) set(kid string, pub *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keySet = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     kid,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
}

func (s *jwksServer) handler(w http.ResponseWriter, _ *http.Request) {
	s.fetches.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.keySet); err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
	}
}

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// TestFindKey_UnknownKidForcesRefresh pins the rotation guarantee: when a
// token arrives signed by a freshly rotated-in key whose kid is not in the
// cached set, FindKey must bypass the TTL and fetch the new set immediately
// -- otherwise rotated-in keys fail validation for up to the TTL.
func TestFindKey_UnknownKidForcesRefresh(t *testing.T) {
	keyA := newTestKey(t)
	keyB := newTestKey(t)

	js := &jwksServer{}
	js.set("kid-a", &keyA.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(js.handler))
	defer srv.Close()

	f := NewJWKSFetcher(srv.URL)
	ctx := context.Background()

	// Warm the cache with kid-a.
	found, err := f.FindKey(ctx, "kid-a")
	if err != nil {
		t.Fatalf("FindKey(kid-a): %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("FindKey(kid-a) returned %d keys, want 1", len(found))
	}

	// Rotate: the provider now serves kid-b. The cache still holds kid-a
	// and is well within its 5-minute TTL.
	js.set("kid-b", &keyB.PublicKey)

	found, err = f.FindKey(ctx, "kid-b")
	if err != nil {
		t.Fatalf("FindKey(kid-b) after rotation: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("FindKey(kid-b) returned %d keys, want 1 (forced refresh must bypass TTL)", len(found))
	}
	if found[0].KeyID != "kid-b" {
		t.Errorf("found key ID = %q, want kid-b", found[0].KeyID)
	}
}

// TestFindKey_ForcedRefreshRateLimited pins the stampede guard: unknown-kid
// lookups force at most one real fetch per minForceInterval. A flood of
// bogus kids must not hammer the JWKS endpoint.
func TestFindKey_ForcedRefreshRateLimited(t *testing.T) {
	keyA := newTestKey(t)

	js := &jwksServer{}
	js.set("kid-a", &keyA.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(js.handler))
	defer srv.Close()

	f := NewJWKSFetcher(srv.URL)
	f.minForceInterval = time.Hour // make the rate limit unmissable in-test
	ctx := context.Background()

	// Warm the cache (fetch #1).
	if _, err := f.FindKey(ctx, "kid-a"); err != nil {
		t.Fatalf("FindKey(kid-a): %v", err)
	}

	// First unknown kid triggers a forced refresh (fetch #2).
	if got, err := f.FindKey(ctx, "kid-bogus-1"); err != nil {
		t.Fatalf("FindKey(kid-bogus-1): %v", err)
	} else if len(got) != 0 {
		t.Errorf("FindKey(kid-bogus-1) returned %d keys, want 0", len(got))
	}
	after := js.fetches.Load()

	// Subsequent unknown kids inside the rate-limit window must be served
	// from the cached set without another fetch.
	for i := 0; i < 10; i++ {
		if got, err := f.FindKey(ctx, "kid-bogus-2"); err != nil {
			t.Fatalf("FindKey(kid-bogus-2): %v", err)
		} else if len(got) != 0 {
			t.Errorf("FindKey(kid-bogus-2) returned %d keys, want 0", len(got))
		}
	}
	if js.fetches.Load() != after {
		t.Errorf("rate-limited forced refresh fetched %d more times, want 0",
			js.fetches.Load()-after)
	}
}
