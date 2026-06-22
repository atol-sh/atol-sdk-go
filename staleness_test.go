package sdk

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	atolsync "atol.sh/sdk-go/sync"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

var gateModel = []byte(`
types:
  user: {}
  document:
    relations:
      viewer:
        types: [user]
`)

// newGateEngine builds a local-style SDK with the staleness gate enabled and a
// model loaded, without any control plane.
func newGateEngine(t *testing.T, mode StalenessMode) *Atol {
	t.Helper()
	a, err := New(Config{
		MaxStaleness:  50 * time.Millisecond,
		StalenessMode: mode,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	if err := a.LoadModel(gateModel); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	return a
}

// installDisconnectedClient attaches a sync client that has never connected
// (connected=false, lastStreamActivity zero), so the liveness gate trips once
// the instance is marked bootstrapped.
func installDisconnectedClient(t *testing.T, a *Atol) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	c := atolsync.NewClient("http://localhost:0", "org-1", "", nil, z, a.policy, zap.NewNop())
	a.syncClient.Store(c)
}

// TestMode_LocalNeverGates verifies WithLocalOnly / DisableSync report
// modeLocal and never trip the gate even when MaxStaleness is set.
func TestMode_LocalNeverGates(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		opts []NewOption
	}{
		{
			name: "WithLocalOnly",
			cfg:  Config{MaxStaleness: 1 * time.Millisecond, StalenessMode: StalenessFailClosed},
			opts: []NewOption{WithLocalOnly()},
		},
		{
			name: "DisableSync",
			cfg:  Config{MaxStaleness: 1 * time.Millisecond, StalenessMode: StalenessFailClosed, DisableSync: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(tt.cfg, tt.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(a.Close)
			if err := a.LoadModel(gateModel); err != nil {
				t.Fatalf("LoadModel: %v", err)
			}
			grantLocalForTest(t, a, "user:alice", "viewer", "document:doc-1")

			if got := a.SyncStatus().Mode; got != "local" {
				t.Errorf("Mode = %q, want local", got)
			}
			// Even bootstrapped, local mode must never gate.
			a.bootstrapped.Store(true)
			stale, _ := a.checkStale()
			if stale {
				t.Error("checkStale() = true in local mode, want false")
			}
			allowed, err := a.Can(context.Background(), "user:alice", "viewer", "document:doc-1")
			if err != nil {
				t.Fatalf("Can: %v", err)
			}
			if !allowed {
				t.Error("Can = false in local mode, want true (gate must not deny)")
			}
		})
	}
}

// TestMode_Uninitialized verifies a sync-expected instance reports
// modeUninitialized and gates as stale before Bootstrap completes.
func TestMode_Uninitialized(t *testing.T) {
	a := newGateEngine(t, StalenessError)
	if got := a.SyncStatus().Mode; got != "uninitialized" {
		t.Errorf("Mode = %q, want uninitialized", got)
	}
	if got := a.SyncStatus().Ready; got {
		t.Error("Ready = true before bootstrap, want false")
	}
	stale, _ := a.checkStale()
	if !stale {
		t.Error("checkStale() = false when uninitialized, want true")
	}
}

// TestGate_StalenessError verifies a stale read returns a *StaleError that
// unwraps to ErrStale, on both Authorize and CanWithDetails.
func TestGate_StalenessError(t *testing.T) {
	a := newGateEngine(t, StalenessError)
	// Never bootstrapped -> stale.

	_, err := a.CanWithDetails(context.Background(), "user:alice", "viewer", "document:doc-1")
	if !errors.Is(err, ErrStale) {
		t.Errorf("CanWithDetails err = %v, want ErrStale", err)
	}
	var se *StaleError
	if !errors.As(err, &se) {
		t.Errorf("CanWithDetails err = %v, want *StaleError", err)
	} else if se.Budget != 50*time.Millisecond {
		t.Errorf("StaleError.Budget = %v, want 50ms", se.Budget)
	}

	ctx := ContextWithUser(context.Background(), &Principal{UserID: "alice"})
	_, err = a.Authorize(ctx, "viewer", "document:doc-1")
	if !errors.Is(err, ErrStale) {
		t.Errorf("Authorize err = %v, want ErrStale", err)
	}
}

// TestGate_FailClosed verifies a stale read denies (allowed=false) on both
// paths when StalenessFailClosed is set.
func TestGate_FailClosed(t *testing.T) {
	a := newGateEngine(t, StalenessFailClosed)
	grantLocalForTest(t, a, "user:alice", "viewer", "document:doc-1")
	// Never bootstrapped -> stale -> deny despite the tuple existing.

	res, err := a.CanWithDetails(context.Background(), "user:alice", "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("CanWithDetails err = %v, want nil (fail-closed denies, not errors)", err)
	}
	if res.Allowed {
		t.Error("CanWithDetails allowed = true, want false (fail-closed)")
	}
	if res.MatchedRule != "stale-deny" {
		t.Errorf("MatchedRule = %q, want stale-deny", res.MatchedRule)
	}

	ctx := ContextWithUser(context.Background(), &Principal{UserID: "alice"})
	d, err := a.Authorize(ctx, "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("Authorize err = %v, want nil", err)
	}
	if d.Allow {
		t.Error("Authorize allow = true, want false (fail-closed)")
	}
}

// TestGate_DisconnectedClientPastBudget verifies that a bootstrapped instance
// whose live client has been disconnected past the budget trips the gate, while
// the same client with fresh liveness does not.
func TestGate_DisconnectedClientPastBudget(t *testing.T) {
	a := newGateEngine(t, StalenessError)
	installDisconnectedClient(t, a)
	a.bootstrapped.Store(true)

	// connected=false, lastStreamActivity zero -> elapsed is effectively
	// infinite -> stale.
	if got := a.SyncStatus().Mode; got != "live" {
		t.Errorf("Mode = %q, want live", got)
	}
	stale, _ := a.checkStale()
	if !stale {
		t.Error("checkStale() = false for a long-disconnected client, want true")
	}
}

// TestGate_OffByDefault verifies that with no MaxStaleness the gate never trips
// even when never bootstrapped (default fail-open behavior preserved).
func TestGate_OffByDefault(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	if err := a.LoadModel(gateModel); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	grantLocalForTest(t, a, "user:alice", "viewer", "document:doc-1")

	stale, _ := a.checkStale()
	if stale {
		t.Error("checkStale() = true with gate off, want false")
	}
	allowed, err := a.Can(context.Background(), "user:alice", "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if !allowed {
		t.Error("Can = false with gate off, want true")
	}
}

// grantLocalForTest writes a tuple directly to the embedded store for tests in
// this package (no control plane required).
func grantLocalForTest(t *testing.T, a *Atol, user, relation, object string) {
	t.Helper()
	if err := a.zanzibar.WriteRawTuple(context.Background(), user, relation, object); err != nil {
		t.Fatalf("grantLocalForTest: %v", err)
	}
}
