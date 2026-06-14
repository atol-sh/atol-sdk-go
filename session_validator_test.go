package sdk_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdk "atol.sh/sdk-go"
)

// headerInjectingTransport adds a marker header to every request, standing
// in for the SDK's HMAC-signing transport so the test can verify the
// validator uses the injected authenticated client rather than building
// its own.
type headerInjectingTransport struct {
	header string
	value  string
}

func (t *headerInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set(t.header, t.value)
	return http.DefaultTransport.RoundTrip(r)
}

// drive calls the unexported refresh path once via Start/Stop. Start does
// a synchronous initial refresh, so after Start returns the first refresh
// outcome is observable.
func startOnce(t *testing.T, sv *sdk.SessionValidator) {
	t.Helper()
	sv.Start()
	t.Cleanup(sv.Stop)
}

func TestSessionValidator_RefreshSuccess(t *testing.T) {
	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Auth") == "signed" {
			sawAuth.Store(true)
		}
		if got := r.Header.Get("X-Atol-Org-Id"); got != "org-1" {
			t.Errorf("X-Atol-Org-Id = %q, want %q", got, "org-1")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revoked_session_ids":["jti-revoked-1","jti-revoked-2"]}`))
	}))
	defer srv.Close()

	client := &http.Client{Transport: &headerInjectingTransport{header: "X-Test-Auth", value: "signed"}}
	sv := sdk.NewSessionValidator(srv.URL, "org-1", time.Hour, client, nil)
	startOnce(t, sv)

	if !sawAuth.Load() {
		t.Error("CRL request did not go through the injected authenticated client")
	}
	if !sv.Healthy() {
		t.Errorf("Healthy() = false after successful refresh, LastRefreshError = %v", sv.LastRefreshError())
	}
	if err := sv.LastRefreshError(); err != nil {
		t.Errorf("LastRefreshError() = %v, want nil", err)
	}
	if got := sv.ConsecutiveFailures(); got != 0 {
		t.Errorf("ConsecutiveFailures() = %d, want 0", got)
	}
	if !sv.IsRevoked("jti-revoked-1") {
		t.Error("IsRevoked(jti-revoked-1) = false, want true")
	}
	if sv.IsRevoked("jti-active") {
		t.Error("IsRevoked(jti-active) = true, want false")
	}
}

func TestSessionValidator_Refresh401_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	sv := sdk.NewSessionValidator(srv.URL, "org-1", time.Hour, srv.Client(), nil)
	startOnce(t, sv)

	if sv.Healthy() {
		t.Error("Healthy() = true after 401 refresh, want false")
	}
	if err := sv.LastRefreshError(); err == nil {
		t.Error("LastRefreshError() = nil after 401 refresh, want error")
	}
	if got := sv.ConsecutiveFailures(); got != 1 {
		t.Errorf("ConsecutiveFailures() = %d, want 1", got)
	}
}

func TestSessionValidator_NetworkError_Unhealthy(t *testing.T) {
	// Point at a server that is already closed -- guaranteed connection error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	sv := sdk.NewSessionValidator(url, "org-1", time.Hour, nil, nil)
	startOnce(t, sv)

	if sv.Healthy() {
		t.Error("Healthy() = true after network error, want false")
	}
	if err := sv.LastRefreshError(); err == nil {
		t.Error("LastRefreshError() = nil after network error, want error")
	}
}

func TestSessionValidator_RecoversAfterFailure(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"revoked_session_ids":["jti-x"]}`))
	}))
	defer srv.Close()

	// Short poll interval so the recovery refresh happens quickly.
	sv := sdk.NewSessionValidator(srv.URL, "org-1", 20*time.Millisecond, srv.Client(), nil)
	startOnce(t, sv)

	if sv.Healthy() {
		t.Fatal("Healthy() = true after failing refresh, want false")
	}

	fail.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sv.Healthy() && sv.IsRevoked("jti-x") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("validator did not recover: healthy=%v revoked=%v lastErr=%v",
		sv.Healthy(), sv.IsRevoked("jti-x"), sv.LastRefreshError())
}
