package sdk

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestWithMetrics_RegistersOnCallerRegistry verifies the collectors register
// against the caller-supplied registry, never the global default.
func TestWithMetrics_RegistersOnCallerRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	a, err := New(Config{}, WithMetrics(reg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)

	if a.metrics == nil {
		t.Fatal("metrics not installed")
	}

	// Push a snapshot and confirm the gauges/counter are gathered.
	a.metrics.observe(SyncStatus{Connected: true, Lag: 3 * time.Second, Rebootstraps: 2})

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	for _, want := range []string{
		"atol_sdk_sync_connected",
		"atol_sdk_sync_lag_seconds",
		"atol_sdk_sync_rebootstraps_total",
	} {
		if !names[want] {
			t.Errorf("metric %q not registered on caller registry (got %v)", want, keys(names))
		}
	}
}

// TestWithMetrics_NilSafe verifies that without WithMetrics there are no
// collectors and the refresh loop is a no-op (no panic).
func TestWithMetrics_NilSafe(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	if a.metrics != nil {
		t.Error("metrics installed without WithMetrics")
	}
	// SyncStatus must not panic when there is no sync client yet.
	if got := a.SyncStatus().Mode; got != "uninitialized" {
		t.Errorf("Mode = %q, want uninitialized", got)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
