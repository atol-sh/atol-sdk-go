package sync

import "time"

// Status is a point-in-time snapshot of the sync client's freshness state
// (ADR 0018). It is assembled under the client mutex so all fields reflect a
// single consistent observation.
type Status struct {
	// Connected reports whether a stream is currently open.
	Connected bool
	// LastStreamActivity is the LOCAL clock reading of the last observed stream
	// event (open or successful Receive) -- the liveness signal.
	LastStreamActivity time.Time
	// LastAppliedAt is the SERVER clock decoded from the newest continuation
	// token's ULID -- the data-age signal. Zero when no parseable token has
	// been applied.
	LastAppliedAt time.Time
	// Lag is the gap between the latest server-applied time and now. It is an
	// observability hint only and is never used to gate reads (cross-host clock
	// skew would corrupt it).
	Lag time.Duration
	// LastToken is the latest continuation token held by the client.
	LastToken string
	// Rebootstraps counts successful rebootstraps since construction.
	Rebootstraps int
}

// Status returns a consistent snapshot of the client's freshness state.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()

	var lag time.Duration
	if !c.lastAppliedServerTime.IsZero() {
		lag = time.Since(c.lastAppliedServerTime)
	}

	return Status{
		Connected:          c.connected,
		LastStreamActivity: c.lastStreamActivity,
		LastAppliedAt:      c.lastAppliedServerTime,
		Lag:                lag,
		LastToken:          c.continuationToken,
		Rebootstraps:       c.rebootstraps,
	}
}
