package sdk

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// prometheusRegisterer is the subset of *prometheus.Registry the SDK needs to
// register its collectors. WithMetrics accepts a caller-supplied registry, so
// the SDK never touches the global default registry (which would risk
// duplicate-registration panics in host apps). A *prometheus.Registry
// satisfies this interface.
type prometheusRegisterer = prometheus.Registerer

// syncMetrics holds the SDK's live-sync Prometheus collectors, registered
// against a caller-supplied registry (ADR 0018).
type syncMetrics struct {
	connected    prometheus.Gauge
	lagSeconds   prometheus.Gauge
	rebootstraps prometheus.Counter

	lastRebootstraps int
}

// newSyncMetrics registers the SDK collectors against reg. It never uses the
// global default registry.
func newSyncMetrics(reg prometheusRegisterer) (*syncMetrics, error) {
	m := &syncMetrics{
		connected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "atol_sdk_sync_connected",
			Help: "1 when the embedded SDK live-sync stream is connected, 0 otherwise.",
		}),
		lagSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "atol_sdk_sync_lag_seconds",
			Help: "Seconds between the newest server-applied mutation time and now (observability only).",
		}),
		rebootstraps: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "atol_sdk_sync_rebootstraps_total",
			Help: "Total successful SDK re-bootstraps.",
		}),
	}
	for _, c := range []prometheus.Collector{m.connected, m.lagSeconds, m.rebootstraps} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// observe updates the collectors from a SyncStatus snapshot. The rebootstrap
// counter is monotonic, so it advances by the delta since the last observation.
func (m *syncMetrics) observe(s SyncStatus) {
	if s.Connected {
		m.connected.Set(1)
	} else {
		m.connected.Set(0)
	}
	m.lagSeconds.Set(s.Lag.Seconds())
	if delta := s.Rebootstraps - m.lastRebootstraps; delta > 0 {
		m.rebootstraps.Add(float64(delta))
		m.lastRebootstraps = s.Rebootstraps
	}
}

// startMetricsRefresh launches a background loop that periodically pushes the
// current SyncStatus into the Prometheus collectors. It is a no-op when
// WithMetrics was not supplied. It exits when ctx is cancelled.
func (a *Atol) startMetricsRefresh(ctx context.Context) {
	if a.metrics == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.metrics.observe(a.SyncStatus())
			}
		}
	}()
}
