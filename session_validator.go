package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	connect "connectrpc.com/connect"
	"go.uber.org/zap"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	atolidentity "atol.sh/sdk-go/identity"
)

// crlErrorThreshold is the number of consecutive refresh failures after
// which the session validator escalates from Warn to Error logging.
const crlErrorThreshold = 3

// crlSnapshotLimit is the maximum complete snapshot returned by the control
// plane. A response at this boundary may be truncated by an older server.
const crlSnapshotLimit = 10000

// ErrTokenSessionRejected means a token's session is revoked or its required
// revocation state is unavailable.
var ErrTokenSessionRejected = errors.New("token session rejected")

// SessionValidator checks JWTs against a revocation list (CRL) fetched from
// the control plane. It polls the DPAgentService ListRevokedSessions RPC
// periodically and caches the deny list in-memory for O(1) lookups.
//
// The validator never fails open silently: every refresh failure is logged,
// consecutive failures escalate to Error level, and callers can observe
// health via Healthy() and LastRefreshError().
type SessionValidator struct {
	client       apiv1connect.DPAgentServiceClient
	orgID        string // tenant/org ID for scoping
	pollInterval time.Duration
	logger       *zap.Logger

	mu                  sync.RWMutex
	revoked             map[string]struct{} // set of revoked session IDs (JWT jti values)
	denyAll             bool                // authenticated snapshot was incomplete or unusable
	lastAcceptedAsOf    time.Time
	lastRefreshErr      error
	lastSuccessAt       time.Time
	consecutiveFailures int
	stopCh              chan struct{}
}

// NewSessionValidator creates a session validator that polls the control
// plane for revoked sessions scoped to a tenant. Default poll interval is 30
// seconds.
//
// client must be a DPAgentService client backed by the SDK's authenticated
// (HMAC-signing) HTTP client -- the control plane requires API-key
// authentication on the CRL RPC. A nil client is a configuration error, not
// a degraded mode: it is rejected here so a mis-wired validator cannot poll
// unauthenticated forever. A nil logger falls back to zap.NewNop().
func NewSessionValidator(client apiv1connect.DPAgentServiceClient, orgID string, pollInterval time.Duration, logger *zap.Logger) (*SessionValidator, error) {
	if client == nil {
		return nil, fmt.Errorf("session validator requires a DPAgentService client")
	}
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SessionValidator{
		client:       client,
		orgID:        orgID,
		pollInterval: pollInterval,
		logger:       logger,
		revoked:      make(map[string]struct{}),
		stopCh:       make(chan struct{}),
	}, nil
}

// Start begins background polling. Call Stop() to clean up.
func (v *SessionValidator) Start() {
	// Initial fetch.
	v.refreshAndRecord()

	go func() {
		ticker := time.NewTicker(v.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				v.refreshAndRecord()
			case <-v.stopCh:
				return
			}
		}
	}()
}

// Stop halts background polling.
func (v *SessionValidator) Stop() {
	close(v.stopCh)
}

// IsRevoked returns true if the given session ID (JWT jti) has been revoked.
func (v *SessionValidator) IsRevoked(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, revoked := v.revoked[sessionID]
	return revoked
}

// RejectsSession reports whether a session is listed as revoked or the last
// authenticated CRL response was unusable, making the deny list incomplete.
func (v *SessionValidator) RejectsSession(sessionID string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.denyAll {
		return true
	}
	_, revoked := v.revoked[sessionID]
	return revoked
}

// LastRefreshError returns the error from the most recent refresh attempt,
// or nil if the last refresh succeeded.
func (v *SessionValidator) LastRefreshError() error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastRefreshErr
}

// ConsecutiveFailures returns the number of refresh attempts that have
// failed in a row. Zero means the last refresh succeeded.
func (v *SessionValidator) ConsecutiveFailures() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.consecutiveFailures
}

// Healthy reports whether a successful CRL refresh is recent and the latest
// refresh attempt succeeded. A never-fetched or stale snapshot is unhealthy.
func (v *SessionValidator) Healthy() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.freshLocked()
}

func (v *SessionValidator) freshLocked() bool {
	maxAge := 2 * v.pollInterval
	if maxAge <= 0 || maxAge > time.Minute {
		maxAge = time.Minute
	}
	age := time.Since(v.lastSuccessAt)
	return !v.denyAll && v.lastRefreshErr == nil && !v.lastSuccessAt.IsZero() &&
		age >= 0 && age <= maxAge
}

// FreshAndNotRevoked requires a recent successful complete snapshot and no
// revoked entry for sessionID. It fails closed before the first fetch and on
// refresh failure or staleness.
func (v *SessionValidator) FreshAndNotRevoked(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.freshLocked() {
		return false
	}
	_, revoked := v.revoked[sessionID]
	return !revoked
}

// CheckTokenSession applies revocation checks after signature validation.
// Test-user tokens require a fresh CRL even when ordinary tokens are allowed
// without a configured session validator.
func (a *Atol) CheckTokenSession(claims *atolidentity.AtolClaims, sessionID string) error {
	testToken := claims != nil && (claims.TestUser || claims.AuthMethod == "test")
	if testToken {
		if a.sessionValidator == nil || !a.sessionValidator.FreshAndNotRevoked(sessionID) {
			return ErrTokenSessionRejected
		}
		return nil
	}
	if a.sessionValidator != nil && a.sessionValidator.RejectsSession(sessionID) {
		return ErrTokenSessionRejected
	}
	return nil
}

// refreshAndRecord runs one refresh cycle, recording failure state and
// logging every failure. Consecutive failures escalate to Error level.
func (v *SessionValidator) refreshAndRecord() {
	err := v.refresh()

	v.mu.Lock()
	if err != nil {
		v.lastRefreshErr = err
		v.consecutiveFailures++
	} else {
		v.lastRefreshErr = nil
		v.consecutiveFailures = 0
	}
	failures := v.consecutiveFailures
	v.mu.Unlock()

	if err == nil {
		return
	}
	fields := []zap.Field{
		zap.Error(err),
		zap.Int("consecutive_failures", failures),
		zap.String("tenant_id", v.orgID),
	}
	if failures >= crlErrorThreshold {
		v.logger.Error("session CRL refresh failing; revocations may not be enforced", fields...)
	} else {
		v.logger.Warn("session CRL refresh failed", fields...)
	}
}

// refresh fetches the revoked-session list once and swaps the in-memory set.
func (v *SessionValidator) refresh() error {
	startedAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := v.client.ListRevokedSessions(ctx,
		connect.NewRequest(&apiv1.ListRevokedSessionsRequest{OrgId: v.orgID}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeResourceExhausted {
			v.rejectIncompleteSnapshot()
		}
		return fmt.Errorf("fetch session CRL for org %s: %w", v.orgID, err)
	}
	ids := resp.Msg.GetRevokedSessionIds()
	asOf := resp.Msg.GetAsOf()
	if asOf == nil || asOf.CheckValid() != nil {
		v.rejectIncompleteSnapshot()
		return fmt.Errorf("session CRL has no valid as-of timestamp")
	}
	serverAge := time.Since(asOf.AsTime())
	if serverAge < 0 || serverAge > time.Minute {
		v.rejectIncompleteSnapshot()
		return fmt.Errorf("session CRL as-of timestamp is stale or future")
	}

	if len(ids) >= crlSnapshotLimit {
		v.rejectIncompleteSnapshot()
		return fmt.Errorf("session CRL reached snapshot limit")
	}
	newSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		newSet[id] = struct{}{}
	}

	v.mu.Lock()
	if !v.lastAcceptedAsOf.IsZero() && !asOf.AsTime().After(v.lastAcceptedAsOf) {
		v.denyAll = true
		v.mu.Unlock()
		return fmt.Errorf("session CRL as-of timestamp did not advance")
	}
	v.revoked = newSet
	v.denyAll = false
	v.lastAcceptedAsOf = asOf.AsTime()
	v.lastSuccessAt = startedAt
	if asOf.AsTime().Before(startedAt) {
		v.lastSuccessAt = asOf.AsTime()
	}
	v.mu.Unlock()
	return nil
}

func (v *SessionValidator) rejectIncompleteSnapshot() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.denyAll = true
}
