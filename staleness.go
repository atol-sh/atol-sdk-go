package sdk

import (
	"context"
	"errors"
	"fmt"
	"time"

	"atol.sh/sdk-go/decision"
	policyengine "atol.sh/sdk-go/policy/engine"
)

// StalenessMode selects how the opt-in staleness gate (ADR 0018) handles a
// read served from a snapshot that may be too old.
type StalenessMode int

const (
	// StalenessOff disables the gate. Reads keep their default
	// fail-open-on-partition behavior. This is the zero value.
	StalenessOff StalenessMode = iota
	// StalenessError surfaces a typed *StaleError (wrapping ErrStale) so the
	// caller decides per call site. Default when WithMaxStaleness is set.
	StalenessError
	// StalenessFailClosed denies the read (allowed=false) and records a
	// decision-log entry with MatchedRule="stale-deny".
	StalenessFailClosed
)

// ErrStale is the sentinel a *StaleError unwraps to, so callers can match with
// errors.Is(err, ErrStale).
var ErrStale = errors.New("authorization snapshot is stale")

// StaleError reports that the staleness gate tripped: the embedded snapshot has
// not been refreshed within Budget. Since is how long the stream has been
// disconnected (zero when the instance was never bootstrapped).
type StaleError struct {
	Since  time.Duration
	Budget time.Duration
}

func (e *StaleError) Error() string {
	return fmt.Sprintf("authorization snapshot is stale: disconnected for %s, budget %s", e.Since, e.Budget)
}

// Unwrap returns ErrStale so errors.Is(err, ErrStale) works.
func (e *StaleError) Unwrap() error { return ErrStale }

// syncMode classifies how the SDK is wired with respect to live sync, so
// SyncStatus consumers do not false-alarm and the gate knows when never to
// trip.
type syncMode int

const (
	// modeLocal means sync is intentionally off (WithLocalOnly or
	// DisableSync). The gate NEVER trips in this mode.
	modeLocal syncMode = iota
	// modeUninitialized means sync is expected but Bootstrap has not completed.
	// The gate treats this as stale.
	modeUninitialized
	// modeLive means the instance has bootstrapped and live sync is running.
	modeLive
)

// mode reports the current sync mode without inferring it from a nil sync
// client pointer.
func (a *Atol) mode() syncMode {
	if a.localOnly || a.config.DisableSync {
		return modeLocal
	}
	if a.bootstrapped.Load() {
		return modeLive
	}
	return modeUninitialized
}

// evaluateGated is the single read path shared by Authorize and CanWithDetails.
// It applies the staleness gate (when enabled) and then evaluates the policy.
// staleResult is non-nil only when the gate trips in fail-closed mode, in which
// case it carries the deny decision and the caller must NOT call policy.Evaluate.
func (a *Atol) evaluateGated(ctx context.Context, input policyengine.EvalInput) (result *policyengine.EvalResult, staleResult *policyengine.EvalResult, err error) {
	if stale, since := a.checkStale(); stale {
		switch a.config.StalenessMode {
		case StalenessError:
			return nil, nil, &StaleError{Since: since, Budget: a.config.MaxStaleness}
		case StalenessFailClosed:
			return nil, &policyengine.EvalResult{Allowed: false, MatchedRule: "stale-deny"}, nil
		}
	}
	res, err := a.policy.Evaluate(ctx, input)
	return res, nil, err
}

// checkStale reports whether the staleness gate should trip and, when it does,
// how long the stream has been disconnected. The gate is liveness-only: it
// never differences the server ULID time against local now. It is off unless
// MaxStaleness > 0 and StalenessMode != StalenessOff.
func (a *Atol) checkStale() (stale bool, since time.Duration) {
	if a.config.StalenessMode == StalenessOff || a.config.MaxStaleness <= 0 {
		return false, 0
	}
	// Local mode (WithLocalOnly / DisableSync) is intentionally not synced and
	// must never gate.
	if a.mode() == modeLocal {
		return false, 0
	}
	// Never bootstrapped: gate as stale (no since to report).
	if !a.bootstrapped.Load() {
		return true, 0
	}
	client := a.syncClient.Load()
	if client == nil {
		// Bootstrapped without a live sync client (e.g. empty continuation
		// token): there is no liveness signal, so treat as stale.
		return true, 0
	}
	status := client.Status()
	if status.Connected {
		return false, 0
	}
	since = time.Since(status.LastStreamActivity)
	if since > a.config.MaxStaleness {
		return true, since
	}
	return false, 0
}

// SyncStatus reports the SDK's live-sync freshness for observability (ADR 0018).
type SyncStatus struct {
	// Mode is "live", "local", or "uninitialized".
	Mode string
	// Ready reports whether the instance has bootstrapped at least once.
	Ready bool
	// Connected reports whether the live stream is currently open.
	Connected bool
	// Lag is the observability-only gap between the latest server-applied time
	// and now. Never used for gating.
	Lag time.Duration
	// LastAppliedAt is the server clock of the newest applied continuation token.
	LastAppliedAt time.Time
	// BootstrapAt is when the last (re)bootstrap completed. Bounds policy age,
	// which the per-mutation lag does not yet cover (see ADR 0022).
	BootstrapAt time.Time
	// Rebootstraps counts successful rebootstraps since construction.
	Rebootstraps int
}

// SyncStatus returns a snapshot of live-sync freshness. It is nil-safe: a
// never-bootstrapped or local-only instance reports Mode accordingly with no
// client state.
func (a *Atol) SyncStatus() SyncStatus {
	s := SyncStatus{
		Ready:       a.bootstrapped.Load(),
		BootstrapAt: a.bootstrapAt(),
	}
	switch a.mode() {
	case modeLocal:
		s.Mode = "local"
	case modeLive:
		s.Mode = "live"
	default:
		s.Mode = "uninitialized"
	}

	if client := a.syncClient.Load(); client != nil {
		st := client.Status()
		s.Connected = st.Connected
		s.Lag = st.Lag
		s.LastAppliedAt = st.LastAppliedAt
		s.Rebootstraps = st.Rebootstraps
	}
	return s
}

// stale-deny decision logging: route both gated read paths through this so a
// fail-closed denial is auditable on Authorize and CanWithDetails alike.
func (a *Atol) logStaleDeny(user, relation, object, authMethod string) {
	if a.decisionLogger == nil {
		return
	}
	a.decisionLogger.Log(decision.Entry{
		User:        user,
		Relation:    relation,
		Object:      object,
		AuthMethod:  authMethod,
		Allowed:     false,
		MatchedRule: "stale-deny",
	})
}
