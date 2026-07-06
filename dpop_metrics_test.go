package sdk

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestDPoPMetrics_RegistersAndRecordsByReason(t *testing.T) {
	reg := prometheus.NewRegistry()
	a, err := New(Config{}, WithMetrics(reg))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)

	dv := a.DPoPValidator()
	if dv.metrics == nil {
		t.Fatal("dpop metrics not installed with WithMetrics")
	}

	// Record one of each distinguished outcome plus the generic bucket.
	dv.metrics.recordOutcome(nil)
	dv.metrics.recordOutcome(ErrDPoPJKTMismatch)
	dv.metrics.recordOutcome(ErrDPoPReplay)
	dv.metrics.recordOutcome(ErrDPoPATHMismatch)
	dv.metrics.recordOutcome(errors.New("something else"))

	counts := gatherOutcomeCounts(t, reg)
	for reason, want := range map[string]float64{
		dpopOutcomeAccepted:    1,
		dpopOutcomeKeyMismatch: 1,
		dpopOutcomeReplay:      1,
		dpopOutcomeATHMismatch: 1,
		dpopOutcomeRejected:    1,
	} {
		if counts[reason] != want {
			t.Errorf("reason %q count = %v, want %v", reason, counts[reason], want)
		}
	}
}

func TestDPoPMetrics_NilSafe(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	// Without WithMetrics the validator's metrics are nil; recording must be
	// a no-op, not a panic.
	a.DPoPValidator().metrics.recordOutcome(ErrDPoPReplay)
}

func gatherOutcomeCounts(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "atol_sdk_dpop_outcomes_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var reason string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "reason" {
					reason = lp.GetValue()
				}
			}
			out[reason] = m.GetCounter().GetValue()
		}
	}
	return out
}
