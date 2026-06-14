package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// crlErrorThreshold is the number of consecutive refresh failures after
// which the session validator escalates from Warn to Error logging.
const crlErrorThreshold = 3

// SessionValidator checks JWTs against a revocation list (CRL) fetched
// from the control plane. It polls GET /api/v1/sessions/revoked periodically
// and caches the deny list in-memory for O(1) lookups.
//
// The validator never fails open silently: every refresh failure is logged,
// consecutive failures escalate to Error level, and callers can observe
// health via Healthy() and LastRefreshError().
type SessionValidator struct {
	controlPlaneURL string
	orgID           string // tenant/org ID for scoping
	pollInterval    time.Duration
	client          *http.Client
	logger          *zap.Logger

	mu                  sync.RWMutex
	revoked             map[string]struct{} // set of revoked session IDs (JWT jti values)
	lastRefreshErr      error
	consecutiveFailures int
	stopCh              chan struct{}
}

// NewSessionValidator creates a session validator that polls the control plane
// for revoked sessions scoped to a tenant. Default poll interval is 30 seconds.
//
// client must be the SDK's authenticated (HMAC-signing) HTTP client -- the
// control plane requires API-key authentication on the CRL endpoint. A nil
// client falls back to a plain client with a 5s timeout (useful only against
// unauthenticated test servers). A nil logger falls back to zap.NewNop().
func NewSessionValidator(controlPlaneURL, orgID string, pollInterval time.Duration, client *http.Client, logger *zap.Logger) *SessionValidator {
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SessionValidator{
		controlPlaneURL: controlPlaneURL,
		orgID:           orgID,
		pollInterval:    pollInterval,
		client:          client,
		logger:          logger,
		revoked:         make(map[string]struct{}),
		stopCh:          make(chan struct{}),
	}
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

// Healthy reports whether the most recent CRL refresh succeeded. While
// unhealthy, the validator serves the last successfully fetched deny list,
// which may be stale -- revocations issued since then are not yet enforced.
func (v *SessionValidator) Healthy() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastRefreshErr == nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/v1/sessions/revoked", v.controlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build CRL request %s: %w", url, err)
	}
	if v.orgID != "" {
		req.Header.Set("X-Atol-Org-Id", v.orgID)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain a bounded amount so the connection can be reused; the body
		// content is intentionally not surfaced (may contain server detail).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("CRL endpoint %s returned status %d", url, resp.StatusCode)
	}

	var body struct {
		RevokedSessionIDs []string `json:"revoked_session_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode CRL response from %s: %w", url, err)
	}

	newSet := make(map[string]struct{}, len(body.RevokedSessionIDs))
	for _, id := range body.RevokedSessionIDs {
		newSet[id] = struct{}{}
	}

	v.mu.Lock()
	v.revoked = newSet
	v.mu.Unlock()
	return nil
}
