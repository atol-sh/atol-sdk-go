package device

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// flippableDPAgent serves a bound-device snapshot whose Found flag can flip from
// false to true mid-test (simulating a session that binds a device after start),
// and counts how many times the snapshot is fetched.
type flippableDPAgent struct {
	apiv1connect.UnimplementedDPAgentServiceHandler

	mu    sync.Mutex
	found bool
	calls int32
}

func (f *flippableDPAgent) GetSessionDeviceSnapshot(_ context.Context, _ *connect.Request[apiv1.GetSessionDeviceSnapshotRequest]) (*connect.Response[apiv1.GetSessionDeviceSnapshotResponse], error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	found := f.found
	f.mu.Unlock()
	return connect.NewResponse(&apiv1.GetSessionDeviceSnapshotResponse{
		Found: found, DeviceId: "dev1", BrowserFamily: "chrome",
	}), nil
}

func (f *flippableDPAgent) setFound(v bool) {
	f.mu.Lock()
	f.found = v
	f.mu.Unlock()
}

func (f *flippableDPAgent) callCount() int32 { return atomic.LoadInt32(&f.calls) }

// TestSnapshotCache_NegativeNotPinned proves the drift-detection blind window is
// bounded: a "no bound device" snapshot is cached only for negativeSnapshotTTL,
// so a device that binds shortly after session start is picked up promptly --
// while a positive snapshot keeps the full ttl.
func TestSnapshotCache_NegativeNotPinned(t *testing.T) {
	fake := &flippableDPAgent{found: false}
	_, handler := apiv1connect.NewDPAgentServiceHandler(fake)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := apiv1connect.NewDPAgentServiceClient(srv.Client(), srv.URL)

	cache := newSnapshotCache(client, 5*time.Minute, 16)
	now := time.Unix(1000, 0)
	cache.now = func() time.Time { return now }

	ctx := context.Background()

	// First fetch: no bound device yet.
	if snap := cache.get(ctx, "org", "sess"); snap.GetFound() {
		t.Fatal("snapshot Found = true, want false (nothing bound yet)")
	}
	if got := fake.callCount(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}

	// Within negativeTTL: served from cache, no re-fetch.
	now = now.Add(5 * time.Second)
	cache.get(ctx, "org", "sess")
	if got := fake.callCount(); got != 1 {
		t.Fatalf("calls within negativeTTL = %d, want 1 (cached)", got)
	}

	// Device binds; once past negativeTTL the next get re-fetches and sees it.
	fake.setFound(true)
	now = now.Add(negativeSnapshotTTL)
	if snap := cache.get(ctx, "org", "sess"); !snap.GetFound() {
		t.Fatal("snapshot Found = false, want true after binding + negativeTTL")
	}
	if got := fake.callCount(); got != 2 {
		t.Fatalf("calls after negativeTTL = %d, want 2 (re-fetched)", got)
	}

	// The positive snapshot is pinned for the full ttl: no re-fetch within it.
	now = now.Add(1 * time.Minute)
	cache.get(ctx, "org", "sess")
	if got := fake.callCount(); got != 2 {
		t.Fatalf("calls within positive ttl = %d, want 2 (cached)", got)
	}

	// After the full ttl elapses, it re-fetches.
	now = now.Add(5 * time.Minute)
	cache.get(ctx, "org", "sess")
	if got := fake.callCount(); got != 3 {
		t.Fatalf("calls after ttl = %d, want 3 (re-fetched)", got)
	}
}
