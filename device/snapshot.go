package device

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// clock is overridable in tests; production uses time.Now.
type clock func() time.Time

// negativeSnapshotTTL bounds how long a "no bound device" snapshot is cached.
// It is far shorter than the positive ttl because a missing binding is a
// transient startup state that flips as soon as the client fingerprints
// (typically within a second of session start). Pinning the negative result for
// the full ttl would blind drift detection for that whole window, letting a
// replayed token slip through unobserved.
const negativeSnapshotTTL = 15 * time.Second

// snapshotCache lazily fetches and caches the device bound to a session, keyed
// by session ID (jti). Entries expire after ttl so a revoked or re-bound
// session is re-fetched -- except a "not found" snapshot, which expires after
// the much shorter negativeTTL so a freshly-bound device becomes detectable
// almost immediately. The cache is bounded; once it reaches maxEntries the
// oldest entries are evicted.
type snapshotCache struct {
	client      apiv1connect.DPAgentServiceClient
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int
	now         clock

	mu    sync.Mutex
	cache map[string]snapshotEntry
}

type snapshotEntry struct {
	snap      *apiv1.GetSessionDeviceSnapshotResponse
	fetchedAt time.Time
}

func newSnapshotCache(client apiv1connect.DPAgentServiceClient, ttl time.Duration, maxEntries int) *snapshotCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	negativeTTL := min(negativeSnapshotTTL, ttl)
	return &snapshotCache{
		client:      client,
		ttl:         ttl,
		negativeTTL: negativeTTL,
		maxEntries:  maxEntries,
		now:         time.Now,
		cache:       make(map[string]snapshotEntry),
	}
}

// entryTTL returns the cache lifetime for a snapshot: the short negativeTTL for
// a session with no bound device (so binding is picked up quickly), the full
// ttl once a device is bound.
func (c *snapshotCache) entryTTL(snap *apiv1.GetSessionDeviceSnapshotResponse) time.Duration {
	if snap == nil || !snap.GetFound() {
		return c.negativeTTL
	}
	return c.ttl
}

// get returns the cached snapshot for a session (scoped by org), fetching it
// lazily on a miss. A fetch failure returns nil so the caller fails open (the
// request proceeds) rather than blocking on the control plane -- consistent
// with the SDK's offline-first posture.
func (c *snapshotCache) get(ctx context.Context, orgID, sessionID string) *apiv1.GetSessionDeviceSnapshotResponse {
	key := orgID + "|" + sessionID
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && c.now().Sub(e.fetchedAt) < c.entryTTL(e.snap) {
		c.mu.Unlock()
		return e.snap
	}
	c.mu.Unlock()

	resp, err := c.client.GetSessionDeviceSnapshot(ctx, connect.NewRequest(&apiv1.GetSessionDeviceSnapshotRequest{
		OrgId:     orgID,
		SessionId: sessionID,
	}))
	if err != nil {
		return nil
	}

	c.mu.Lock()
	if len(c.cache) >= c.maxEntries {
		c.evictOldestLocked()
	}
	c.cache[key] = snapshotEntry{snap: resp.Msg, fetchedAt: c.now()}
	c.mu.Unlock()
	return resp.Msg
}

// evictOldestLocked removes the least-recently-fetched entry. Caller holds mu.
func (c *snapshotCache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, e := range c.cache {
		if oldestKey == "" || e.fetchedAt.Before(oldest) {
			oldestKey, oldest = k, e.fetchedAt
		}
	}
	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}
