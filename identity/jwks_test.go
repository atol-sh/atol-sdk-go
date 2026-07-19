package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
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

// TestFindKey_DistinctNewKidsWithinRefreshInterval pins the regression where
// a second valid signing key introduced shortly after the first forced refresh
// was rejected from the stale cache for the entire rate-limit interval.
func TestFindKey_DistinctNewKidsWithinRefreshInterval(t *testing.T) {
	keyA := newTestKey(t)
	keyB := newTestKey(t)
	keyC := newTestKey(t)

	js := &jwksServer{}
	js.set("kid-a", &keyA.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(js.handler))
	defer srv.Close()

	f := NewJWKSFetcher(srv.URL)
	f.minForceInterval = 20 * time.Millisecond
	ctx := context.Background()

	if _, err := f.FindKey(ctx, "kid-a"); err != nil {
		t.Fatalf("FindKey(kid-a): %v", err)
	}

	js.set("kid-b", &keyB.PublicKey)
	if got, err := f.FindKey(ctx, "kid-b"); err != nil {
		t.Fatalf("FindKey(kid-b): %v", err)
	} else if len(got) != 1 {
		t.Fatalf("FindKey(kid-b) returned %d keys, want 1", len(got))
	}

	// This lookup starts inside the pacing interval. It must wait for the
	// next allowed refresh and validate kid-c, not return the kid-b snapshot.
	js.set("kid-c", &keyC.PublicKey)
	if got, err := f.FindKey(ctx, "kid-c"); err != nil {
		t.Fatalf("FindKey(kid-c): %v", err)
	} else if len(got) != 1 || got[0].KeyID != "kid-c" {
		t.Fatalf("FindKey(kid-c) = %#v, want one kid-c key", got)
	}

	if got := js.fetches.Load(); got != 3 {
		t.Fatalf("JWKS fetches = %d, want 3", got)
	}
}

// TestFindKey_ForcedRefreshCoalesced pins the stampede guard: concurrent
// unknown-kid lookups against the same snapshot share one paced refresh.
func TestFindKey_ForcedRefreshCoalesced(t *testing.T) {
	keyA := newTestKey(t)

	js := &jwksServer{}
	js.set("kid-a", &keyA.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(js.handler))
	defer srv.Close()

	f := NewJWKSFetcher(srv.URL)
	f.minForceInterval = 20 * time.Millisecond
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

	// Concurrent unknown-kid callers all observe the same snapshot. Exactly
	// one of them performs the next paced refresh and the rest reuse it.
	start := make(chan struct{})
	errs := make(chan error, 10)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := f.FindKey(ctx, "kid-bogus-2")
			if err != nil {
				errs <- err
				return
			}
			if len(got) != 0 {
				errs <- fmt.Errorf("FindKey(kid-bogus-2) returned %d keys, want 0", len(got))
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := js.fetches.Load() - after; got != 1 {
		t.Errorf("coalesced forced refresh fetched %d more times, want 1", got)
	}
}

func TestFindKey_RefreshWaitHonorsContext(t *testing.T) {
	keyA := newTestKey(t)

	js := &jwksServer{}
	js.set("kid-a", &keyA.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(js.handler))
	defer srv.Close()

	f := NewJWKSFetcher(srv.URL)
	f.minForceInterval = time.Hour
	ctx := context.Background()

	if _, err := f.FindKey(ctx, "kid-a"); err != nil {
		t.Fatalf("FindKey(kid-a): %v", err)
	}
	if _, err := f.FindKey(ctx, "kid-bogus-1"); err != nil {
		t.Fatalf("FindKey(kid-bogus-1): %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.FindKey(canceled, "kid-bogus-2"); !errors.Is(err, context.Canceled) {
		t.Fatalf("FindKey with canceled context error = %v, want context.Canceled", err)
	}
}
