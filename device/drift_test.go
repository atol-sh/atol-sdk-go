package device

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// fakeDPAgent serves a fixed bound-device snapshot and records divergence
// reports for assertions.
type fakeDPAgent struct {
	apiv1connect.UnimplementedDPAgentServiceHandler
	snap *apiv1.GetSessionDeviceSnapshotResponse

	mu       sync.Mutex
	reported []*apiv1.DeviceDivergenceEvent
}

func (f *fakeDPAgent) GetSessionDeviceSnapshot(_ context.Context, _ *connect.Request[apiv1.GetSessionDeviceSnapshotRequest]) (*connect.Response[apiv1.GetSessionDeviceSnapshotResponse], error) {
	return connect.NewResponse(f.snap), nil
}

func (f *fakeDPAgent) ReportDeviceDivergence(_ context.Context, stream *connect.ClientStream[apiv1.ReportDeviceDivergenceRequest]) (*connect.Response[apiv1.ReportDeviceDivergenceResponse], error) {
	var n int32
	for stream.Receive() {
		if ev := stream.Msg().GetEvent(); ev != nil {
			f.mu.Lock()
			f.reported = append(f.reported, ev)
			f.mu.Unlock()
			n++
		}
	}
	return connect.NewResponse(&apiv1.ReportDeviceDivergenceResponse{Accepted: n}), nil
}

func (f *fakeDPAgent) reports() []*apiv1.DeviceDivergenceEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*apiv1.DeviceDivergenceEvent, len(f.reported))
	copy(out, f.reported)
	return out
}

func newTestDetector(t *testing.T, snap *apiv1.GetSessionDeviceSnapshotResponse) (*DriftDetector, *fakeDPAgent) {
	t.Helper()
	fake := &fakeDPAgent{snap: snap}
	_, handler := apiv1connect.NewDPAgentServiceHandler(fake)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := apiv1connect.NewDPAgentServiceClient(srv.Client(), srv.URL)
	return NewDriftDetector(client, DriftConfig{}), fake
}

func reqWithUA(ua, deviceID string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", ua)
	if deviceID != "" {
		r.Header.Set(deviceIDHeader, deviceID)
	}
	return r
}

func TestDriftDetector_DivergentUserAgent(t *testing.T) {
	det, fake := newTestDetector(t, &apiv1.GetSessionDeviceSnapshotResponse{
		Found: true, DeviceId: "dev_chrome", BrowserFamily: "chrome",
	})

	// A curl replay of a chrome-bound session diverges on UA family.
	kind := det.Inspect(context.Background(), "org1", "sess1", "user1", reqWithUA("curl/8.7.1", ""))
	if kind != "user_agent" {
		t.Fatalf("Inspect kind = %q, want user_agent", kind)
	}

	waitFor(t, func() bool { return len(fake.reports()) == 1 })
	ev := fake.reports()[0]
	if ev.GetSessionId() != "sess1" || ev.GetDivergenceKind() != "user_agent" || ev.GetBoundDeviceId() != "dev_chrome" {
		t.Errorf("divergence event = %+v, want session sess1 / user_agent / dev_chrome", ev)
	}

	// Repeated identical divergence is deduped: still exactly one report.
	det.Inspect(context.Background(), "org1", "sess1", "user1", reqWithUA("curl/8.7.1", ""))
	time.Sleep(50 * time.Millisecond)
	if got := len(fake.reports()); got != 1 {
		t.Errorf("reports after dedup = %d, want 1", got)
	}
}

func TestDriftDetector_MatchingClientNoDivergence(t *testing.T) {
	det, fake := newTestDetector(t, &apiv1.GetSessionDeviceSnapshotResponse{
		Found: true, DeviceId: "dev_chrome", BrowserFamily: "chrome",
	})
	// Same browser family + a client fingerprint header: no divergence.
	if kind := det.Inspect(context.Background(), "org1", "sess1", "user1",
		reqWithUA("Mozilla/5.0 (Macintosh) Chrome/148.0.0.0 Safari/537.36", "dev_chrome")); kind != "" {
		t.Fatalf("Inspect kind = %q, want empty", kind)
	}
	time.Sleep(50 * time.Millisecond)
	if got := len(fake.reports()); got != 0 {
		t.Errorf("reports = %d, want 0", got)
	}
}

func TestDriftDetector_BrowserNavigationNotFlagged(t *testing.T) {
	det, fake := newTestDetector(t, &apiv1.GetSessionDeviceSnapshotResponse{
		Found: true, DeviceId: "dev_chrome", BrowserFamily: "chrome",
	})
	// A top-level navigation/refresh by the bound browser carries no device-id
	// header (the JS SDK only sets it on fetch/XHR). It must not be flagged.
	r := reqWithUA("Mozilla/5.0 (Macintosh) Chrome/148.0.0.0 Safari/537.36", "")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	if kind := det.Inspect(context.Background(), "org1", "sess1", "user1", r); kind != "" {
		t.Fatalf("Inspect kind = %q, want empty (legit navigation)", kind)
	}
	time.Sleep(50 * time.Millisecond)
	if got := len(fake.reports()); got != 0 {
		t.Errorf("reports = %d, want 0", got)
	}
}

func TestDriftDetector_NoFingerprintNonNavigationFlagged(t *testing.T) {
	det, fake := newTestDetector(t, &apiv1.GetSessionDeviceSnapshotResponse{
		Found: true, DeviceId: "dev_chrome", BrowserFamily: "chrome",
	})
	// A script-initiated request (Sec-Fetch-Mode: cors) that spoofs the chrome UA
	// but carries no fingerprint is still a divergence: the JS SDK would have
	// attached the device-id header here.
	r := reqWithUA("Mozilla/5.0 (Macintosh) Chrome/148.0.0.0 Safari/537.36", "")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	kind := det.Inspect(context.Background(), "org1", "sess1", "user1", r)
	if kind != "no_fingerprint" {
		t.Fatalf("Inspect kind = %q, want no_fingerprint", kind)
	}
	waitFor(t, func() bool { return len(fake.reports()) == 1 })
}

func TestDriftDetector_NoBoundDevice(t *testing.T) {
	det, fake := newTestDetector(t, &apiv1.GetSessionDeviceSnapshotResponse{Found: false})
	if kind := det.Inspect(context.Background(), "org1", "sess1", "user1", reqWithUA("curl/8.7.1", "")); kind != "" {
		t.Fatalf("Inspect kind = %q, want empty (nothing bound)", kind)
	}
	time.Sleep(50 * time.Millisecond)
	if got := len(fake.reports()); got != 0 {
		t.Errorf("reports = %d, want 0", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
