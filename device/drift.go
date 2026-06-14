package device

import (
	"context"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// DriftDetector compares the live server-side signals of an authenticated
// request against the device bound to its session, and reports divergences to
// the control plane. It exists because a resource server terminates the
// client's TLS itself: the control plane never observes a replayed token's
// signals, so detection must happen here, at the edge, and report only the
// divergences (not every request).
type DriftDetector struct {
	cache    *snapshotCache
	client   apiv1connect.DPAgentServiceClient
	maxSeen  int
	reportTO time.Duration

	mu   sync.Mutex
	seen map[string]struct{} // dedup: (org|session|kind|family) already reported
}

// DriftConfig configures a DriftDetector.
type DriftConfig struct {
	// SnapshotTTL bounds how long a bound-device snapshot is cached per session.
	// Defaults to 5 minutes.
	SnapshotTTL time.Duration
	// MaxSessions bounds the snapshot cache and dedup set. Defaults to 4096.
	MaxSessions int
}

// NewDriftDetector creates a detector that uses the given DPAgentService client.
func NewDriftDetector(client apiv1connect.DPAgentServiceClient, cfg DriftConfig) *DriftDetector {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 4096
	}
	return &DriftDetector{
		cache:    newSnapshotCache(client, cfg.SnapshotTTL, cfg.MaxSessions),
		client:   client,
		maxSeen:  cfg.MaxSessions,
		reportTO: 5 * time.Second,
		seen:     make(map[string]struct{}),
	}
}

// Inspect compares the request against the session's bound device. When the
// live client diverges (different UA family, or no client fingerprint where the
// session was bound to one) it reports a divergence -- at most once per
// (session, kind, family) -- and returns the divergence kind. An empty return
// means no divergence (or nothing to compare against).
//
// Inspect never blocks the request on reporting: the report is sent on a
// detached context in a goroutine.
func (d *DriftDetector) Inspect(ctx context.Context, orgID, sessionID, userID string, r *http.Request) string {
	if sessionID == "" || orgID == "" {
		return ""
	}
	snap := d.cache.get(ctx, orgID, sessionID)
	if snap == nil || !snap.GetFound() {
		// No bound device to diverge from (or snapshot unavailable -- fail open).
		return ""
	}

	ua := r.UserAgent()
	family := uaFamily(ua)
	hasFingerprint := r.Header.Get(deviceIDHeader) != ""

	kind := ""
	switch {
	case snap.GetBrowserFamily() != "" && family != snap.GetBrowserFamily():
		kind = "user_agent"
	case snap.GetDeviceId() != "" && !hasFingerprint && !isBrowserNavigation(r):
		// Missing client fingerprint is only a divergence on a script-initiated
		// request, where the JS SDK would have attached the device-id header. A
		// top-level browser navigation (document load/refresh) never carries it,
		// so flagging those produced false "no_fingerprint" drift against the
		// session's own legitimate device.
		kind = "no_fingerprint"
	}
	if kind == "" {
		return ""
	}

	if !d.markFirst(orgID + "|" + sessionID + "|" + kind + "|" + family) {
		return kind // already reported this divergence shape for the session
	}

	ev := &apiv1.DeviceDivergenceEvent{
		OrgId:             orgID,
		SessionId:         sessionID,
		UserId:            userID,
		BoundDeviceId:     snap.GetDeviceId(),
		ObservedUserAgent: ua,
		ObservedIp:        clientIP(r),
		DivergenceKind:    kind,
		ObservedAt:        timestamppb.New(time.Now()),
	}
	go d.report(ev)
	return kind
}

// report streams a single divergence event to the control plane on a detached,
// time-bounded context. Failures are swallowed -- divergence reporting is
// best-effort telemetry and must never affect the request it describes.
func (d *DriftDetector) report(ev *apiv1.DeviceDivergenceEvent) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), d.reportTO)
	defer cancel()

	stream := d.client.ReportDeviceDivergence(ctx)
	if err := stream.Send(&apiv1.ReportDeviceDivergenceRequest{Event: ev}); err != nil {
		_, _ = stream.CloseAndReceive()
		return
	}
	_, _ = stream.CloseAndReceive()
}

// markFirst records a dedup key and reports whether it was newly added. The set
// is bounded; on overflow it resets (a coarse but allocation-free eviction).
func (d *DriftDetector) markFirst(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return false
	}
	if len(d.seen) >= d.maxSeen {
		d.seen = make(map[string]struct{})
	}
	d.seen[key] = struct{}{}
	return true
}
