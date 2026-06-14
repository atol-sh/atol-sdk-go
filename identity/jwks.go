package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSFetcher fetches and caches JWKS from an OIDC provider.
// Used by the SDK for token validation.
type JWKSFetcher struct {
	mu        sync.RWMutex
	jwksURL   string
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	ttl       time.Duration

	// forcedAt is the time of the last unknown-kid forced refresh.
	// Forced refreshes bypass the TTL (so rotated-in keys validate
	// immediately) but are rate-limited to minForceInterval to prevent
	// a stampede from tokens carrying bogus kids.
	forcedAt         time.Time
	minForceInterval time.Duration
}

// NewJWKSFetcher creates a JWKS fetcher for the given JWKS URL.
func NewJWKSFetcher(jwksURL string) *JWKSFetcher {
	return &JWKSFetcher{
		jwksURL:          jwksURL,
		ttl:              5 * time.Minute,
		minForceInterval: 15 * time.Second,
	}
}

// GetKeys returns the current JWKS, fetching from the remote URL if needed.
func (f *JWKSFetcher) GetKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	f.mu.RLock()
	if f.keys != nil && time.Since(f.fetchedAt) < f.ttl {
		keys := f.keys
		f.mu.RUnlock()
		return keys, nil
	}
	f.mu.RUnlock()

	return f.refresh(ctx)
}

// refresh fetches the JWKS from the remote URL and caches it, respecting
// the TTL (another goroutine may have refreshed while we waited for the
// write lock).
func (f *JWKSFetcher) refresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock.
	if f.keys != nil && time.Since(f.fetchedAt) < f.ttl {
		return f.keys, nil
	}

	return f.fetchLocked(ctx)
}

// forceRefresh fetches the JWKS regardless of TTL. Used on unknown-kid
// cache misses so a freshly rotated-in signing key validates immediately
// instead of failing for up to the TTL. Rate-limited to minForceInterval;
// within the window the current cached set is returned.
func (f *JWKSFetcher) forceRefresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.keys != nil && time.Since(f.forcedAt) < f.minForceInterval {
		return f.keys, nil
	}
	f.forcedAt = time.Now()

	return f.fetchLocked(ctx)
}

// fetchLocked performs the HTTP fetch and updates the cache. Caller must
// hold f.mu.
func (f *JWKSFetcher) fetchLocked(ctx context.Context) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", f.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint %s returned status %d: %s", f.jwksURL, resp.StatusCode, body)
	}

	var keySet jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return nil, fmt.Errorf("decoding JWKS response from %s: %w", f.jwksURL, err)
	}

	f.keys = &keySet
	f.fetchedAt = time.Now()

	return f.keys, nil
}

// FindKey looks up a key by ID from the cached JWKS.
// If the kid is not found in the cached set, it forces a refresh and retries
// once. This handles key rotation and provider restarts where the signing key
// changes while the SDK has stale JWKS cached.
func (f *JWKSFetcher) FindKey(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	keys, err := f.GetKeys(ctx)
	if err != nil {
		return nil, err
	}

	found := keys.Key(kid)
	if len(found) > 0 {
		return found, nil
	}

	// Cache miss — the kid is unknown. Force a real refresh (bypassing the
	// TTL) in case the provider rotated keys or was restarted with a new
	// signing key. Rate-limited inside forceRefresh to prevent stampedes.
	keys, err = f.forceRefresh(ctx)
	if err != nil {
		return nil, err
	}
	return keys.Key(kid), nil
}
