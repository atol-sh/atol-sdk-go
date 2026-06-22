package sync

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/oklog/ulid/v2"

	policyengine "atol.sh/sdk-go/policy/engine"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

func newStatusClient(t *testing.T, token string) *Client {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)
	return NewClient("http://localhost:0", "org-1", token, nil, z, p, zap.NewNop())
}

// TestStatus_LivenessTracking verifies that stream open/activity/close move the
// liveness and connected fields, and that Status reports them consistently.
func TestStatus_LivenessTracking(t *testing.T) {
	c := newStatusClient(t, "")

	if st := c.Status(); st.Connected {
		t.Error("Connected = true before open, want false")
	}

	c.markStreamOpen()
	st := c.Status()
	if !st.Connected {
		t.Error("Connected = false after markStreamOpen, want true")
	}
	if st.LastStreamActivity.IsZero() {
		t.Error("LastStreamActivity is zero after open, want set")
	}

	firstActivity := st.LastStreamActivity
	time.Sleep(2 * time.Millisecond)
	c.markActivity()
	if got := c.Status().LastStreamActivity; !got.After(firstActivity) {
		t.Errorf("LastStreamActivity not advanced by markActivity: %v <= %v", got, firstActivity)
	}

	c.markStreamClosed()
	if st := c.Status(); st.Connected {
		t.Error("Connected = true after markStreamClosed, want false")
	}
}

// TestStatus_TokenServerTimeDecode verifies the continuation token's ULID time
// is decoded into LastAppliedAt, and a non-ULID token leaves it zero.
func TestStatus_TokenServerTimeDecode(t *testing.T) {
	serverTime := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	var u ulid.ULID
	if err := u.SetTime(ulid.Timestamp(serverTime)); err != nil {
		t.Fatalf("SetTime: %v", err)
	}
	token := u.String()

	c := newStatusClient(t, "")
	c.setContinuationToken(token)
	got := c.Status().LastAppliedAt
	// ULID time has millisecond resolution.
	if diff := got.Sub(serverTime); diff < -time.Millisecond || diff > time.Millisecond {
		t.Errorf("LastAppliedAt = %v, want ~%v", got, serverTime)
	}

	// A non-ULID token must not panic and must leave the server time zero.
	c.setContinuationToken("not-a-ulid")
	if got := c.Status().LastAppliedAt; !got.IsZero() {
		t.Errorf("LastAppliedAt = %v for non-ULID token, want zero", got)
	}
}

// TestStatus_RebootstrapCounter verifies onRebootstrap bumps the counter and
// stores the fresh token.
func TestStatus_RebootstrapCounter(t *testing.T) {
	c := newStatusClient(t, "old")
	if got := c.Status().Rebootstraps; got != 0 {
		t.Errorf("Rebootstraps = %d, want 0", got)
	}
	c.onRebootstrap("fresh")
	st := c.Status()
	if st.Rebootstraps != 1 {
		t.Errorf("Rebootstraps = %d, want 1", st.Rebootstraps)
	}
	if st.LastToken != "fresh" {
		t.Errorf("LastToken = %q, want fresh", st.LastToken)
	}
}
