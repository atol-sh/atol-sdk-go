package sdk

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// DPoP outcome reasons. These are the bounded, fixed label values for the
// DPoP outcome counter -- never a jti, user id, or any unbounded value.
const (
	dpopOutcomeAccepted    = "accepted"
	dpopOutcomeRejected    = "rejected"
	dpopOutcomeKeyMismatch = "key_mismatch"
	dpopOutcomeReplay      = "replay"
	dpopOutcomeATHMismatch = "ath_mismatch"
)

// dpopMetrics holds the DPoP outcome counter. Cardinality is bounded by the
// fixed reason set above; the counter is never labeled by jti or user.
type dpopMetrics struct {
	outcomes *prometheus.CounterVec
}

// newDPoPMetrics registers the DPoP outcome counter against reg. It never
// uses the global default registry, matching newSyncMetrics.
func newDPoPMetrics(reg prometheusRegisterer) (*dpopMetrics, error) {
	outcomes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "atol_sdk_dpop_outcomes_total",
		Help: "DPoP proof validation outcomes on resource-server requests, by reason.",
	}, []string{"reason"})
	if err := reg.Register(outcomes); err != nil {
		return nil, err
	}
	return &dpopMetrics{outcomes: outcomes}, nil
}

// withDPoPMetrics installs an outcome recorder on the validator. Internal --
// used by New when WithMetrics supplied a registry.
func withDPoPMetrics(m *dpopMetrics) DPoPValidatorOption {
	return func(v *DPoPValidator) {
		v.metrics = m
	}
}

// record increments the outcome counter for reason. Safe on a nil receiver so
// callers need not branch on whether metrics are configured.
func (m *dpopMetrics) record(reason string) {
	if m == nil {
		return
	}
	m.outcomes.WithLabelValues(reason).Inc()
}

// recordOutcome maps a DPoP validation error to a bounded reason label and
// records it. A nil err records "accepted".
func (m *dpopMetrics) recordOutcome(err error) {
	if m == nil {
		return
	}
	m.record(dpopReason(err))
}

// dpopReason maps a DPoP validation error to a bounded-cardinality reason
// label. The distinguished reasons (key_mismatch, replay, ath_mismatch) are
// the security-relevant signals worth alerting on separately; everything else
// collapses to "rejected". nil maps to "accepted".
func dpopReason(err error) string {
	switch {
	case err == nil:
		return dpopOutcomeAccepted
	case errors.Is(err, ErrDPoPJKTMismatch):
		return dpopOutcomeKeyMismatch
	case errors.Is(err, ErrDPoPReplay):
		return dpopOutcomeReplay
	case errors.Is(err, ErrDPoPATHMismatch):
		return dpopOutcomeATHMismatch
	default:
		return dpopOutcomeRejected
	}
}
