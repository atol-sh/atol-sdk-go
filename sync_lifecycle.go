package sdk

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"atol.sh/sdk-go/bootstrap"
	atolsync "atol.sh/sdk-go/sync"
)

// WithMaxStaleness enables the opt-in staleness gate (ADR 0018). When the live
// stream has been disconnected longer than d, reads are handled per mode:
// StalenessError returns a *StaleError (wrapping ErrStale) so the caller
// decides; StalenessFailClosed denies and logs MatchedRule="stale-deny". The
// gate is liveness-only and never trips for WithLocalOnly/DisableSync
// instances. Passing StalenessOff (or d <= 0) leaves the gate disabled.
func WithMaxStaleness(d time.Duration, mode StalenessMode) NewOption {
	return func(o *newOptions) {
		o.maxStaleness = &d
		o.stalenessMode = &mode
	}
}

// WithMetrics registers the SDK's sync collectors against the caller-supplied
// Prometheus registry (ADR 0018) -- never the global default registry, which
// would risk duplicate-registration panics in host apps. Pass the
// *prometheus.Registry the host owns. When unused, the SDK records no metrics.
func WithMetrics(reg prometheusRegisterer) NewOption {
	return func(o *newOptions) {
		o.metricsReg = reg
	}
}

// WithBootstrapInterval forces a periodic full re-bootstrap to bound policy age
// (ADR 0018). Default 0 (off). The ticker runs on its own lifecycle so it
// bounds policy age even when DisableSync is set; it is stopped by Close.
func WithBootstrapInterval(d time.Duration) NewOption {
	return func(o *newOptions) {
		o.bootstrapInterval = &d
	}
}

// markBootstrapped records that an initial (or repeat) bootstrap completed:
// flips the bootstrapped flag and stamps the bootstrap time.
func (a *Atol) markBootstrapped() {
	a.bootstrapped.Store(true)
	a.bootstrapAtMu.Lock()
	a.bootstrapTime = time.Now()
	a.bootstrapAtMu.Unlock()
}

// bootstrapAt returns when the last (re)bootstrap completed.
func (a *Atol) bootstrapAt() time.Time {
	a.bootstrapAtMu.RLock()
	defer a.bootstrapAtMu.RUnlock()
	return a.bootstrapTime
}

// runBootstrapInterval forces a periodic full re-bootstrap to bound policy age
// (ADR 0018). It runs independently of live sync, so it bounds policy age even
// when DisableSync is set. It exits when ctx is cancelled (via Close -> bgCancel).
func (a *Atol) runBootstrapInterval(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.config.ControlPlaneURL == "" || a.config.StoreID == "" {
				// No control plane to bootstrap from; nothing to refresh.
				continue
			}
			if _, err := a.rebootstrap(ctx); err != nil {
				a.logger.Warn("periodic re-bootstrap failed",
					zap.String("org_id", a.config.StoreID),
					zap.Error(err))
			}
		}
	}
}

// Bootstrap fetches the initial state (model, tuples, bundle, data) from the
// control plane, then starts live sync to receive real-time mutations.
func (a *Atol) Bootstrap(ctx context.Context) error {
	if a.config.ControlPlaneURL == "" {
		return fmt.Errorf("control plane URL not configured")
	}
	if a.config.StoreID == "" {
		return fmt.Errorf("store ID (org ID) not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, a.config.BootstrapTimeout)
	defer cancel()

	result, err := a.bootstrapLoad(ctx)
	if err != nil {
		return err
	}

	a.markBootstrapped()

	// Start live sync to receive real-time mutations from the control plane.
	if !a.config.DisableSync && result != nil && result.ContinuationToken != "" {
		client := atolsync.NewClient(
			a.config.ControlPlaneURL,
			a.config.StoreID,
			result.ContinuationToken,
			a.httpClient,
			a.zanzibar,
			a.policy,
			a.logger.Named("sync"),
			atolsync.WithRebootstrap(a.rebootstrap),
		)
		// Seed the bootstrap dynamic-data overlay so a later bundle swap does
		// not wipe it (ADR 0022). Must precede Run.
		client.SeedPolicyData(result.PolicyData)
		// Publish the pointer before launching the goroutine so request
		// goroutines observe a fully constructed client.
		a.syncClient.Store(client)
		syncCtx, cancel := context.WithCancel(context.Background())
		a.syncCancel = cancel
		go func() {
			a.startMetricsRefresh(syncCtx)
			client.Run(syncCtx)
		}()
	}

	return nil
}

// bootstrapLoad fetches the full state snapshot (model, tuples, bundle, data)
// from the control plane, loads it into the embedded engines, and runs all
// registered materializers.
func (a *Atol) bootstrapLoad(ctx context.Context) (*bootstrap.Result, error) {
	result, err := bootstrap.Bootstrap(ctx, a.config.ControlPlaneURL, a.config.StoreID, a.httpClient, a.zanzibar, a.policy)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// Run all registered materializers after bootstrap to populate SDK-local tuples.
	if err := a.materializers.materializeAll(ctx); err != nil {
		return nil, fmt.Errorf("materialize: %w", err)
	}

	return result, nil
}

// rebootstrap is the sync client's recovery path when the control plane
// refuses the continuation token: it re-runs the full bootstrap load and
// returns the fresh continuation token from the new snapshot.
func (a *Atol) rebootstrap(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.BootstrapTimeout)
	defer cancel()

	result, err := a.bootstrapLoad(ctx)
	if err != nil {
		return "", fmt.Errorf("rebootstrap: %w", err)
	}
	a.markBootstrapped()
	// Refresh the sync client's bootstrap overlay so post-rebootstrap bundle
	// swaps re-apply the fresh dynamic data, not the stale original (ADR 0022).
	if c := a.syncClient.Load(); c != nil {
		c.SeedPolicyData(result.PolicyData)
	}
	return result.ContinuationToken, nil
}
