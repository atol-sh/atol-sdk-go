package sdk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	connect "connectrpc.com/connect"

	sdk "atol.sh/sdk-go"
	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
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

// crlStub implements the DPAgentService with a configurable ListRevokedSessions.
type crlStub struct {
	apiv1connect.UnimplementedDPAgentServiceHandler
	list func(req *apiv1.ListRevokedSessionsRequest, headers http.Header) (*apiv1.ListRevokedSessionsResponse, error)
}

func (s *crlStub) ListRevokedSessions(_ context.Context, req *connect.Request[apiv1.ListRevokedSessionsRequest]) (*connect.Response[apiv1.ListRevokedSessionsResponse], error) {
	resp, err := s.list(req.Msg, req.Header())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// newCRLServer mounts the stub as a real Connect server and returns it.
func newCRLServer(t *testing.T, stub *crlStub) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(apiv1connect.NewDPAgentServiceHandler(stub))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newValidator builds a validator over a DPAgentService client for the given
// server and http client, failing the test on constructor error.
func newValidator(t *testing.T, srvURL string, client *http.Client, orgID string, poll time.Duration) *sdk.SessionValidator {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	dpClient := apiv1connect.NewDPAgentServiceClient(client, srvURL)
	sv, err := sdk.NewSessionValidator(dpClient, orgID, poll, nil)
	if err != nil {
		t.Fatalf("NewSessionValidator: %v", err)
	}
	return sv
}

// startOnce starts the validator; Start does a synchronous initial refresh,
// so after it returns the first refresh outcome is observable.
func startOnce(t *testing.T, sv *sdk.SessionValidator) {
	t.Helper()
	sv.Start()
	t.Cleanup(sv.Stop)
}

func TestSessionValidator_NilClientRejected(t *testing.T) {
	if _, err := sdk.NewSessionValidator(nil, "org-1", time.Hour, nil); err == nil {
		t.Error("NewSessionValidator(nil client) = nil error, want configuration error")
	}
}

func TestSessionValidator_RefreshSuccess(t *testing.T) {
	var sawAuth atomic.Bool
	stub := &crlStub{list: func(req *apiv1.ListRevokedSessionsRequest, headers http.Header) (*apiv1.ListRevokedSessionsResponse, error) {
		if headers.Get("X-Test-Auth") == "signed" {
			sawAuth.Store(true)
		}
		if got := req.GetOrgId(); got != "org-1" {
			t.Errorf("org_id = %q, want %q", got, "org-1")
		}
		return &apiv1.ListRevokedSessionsResponse{
			RevokedSessionIds: []string{"jti-revoked-1", "jti-revoked-2"},
		}, nil
	}}
	srv := newCRLServer(t, stub)

	client := &http.Client{Transport: &headerInjectingTransport{header: "X-Test-Auth", value: "signed"}}
	sv := newValidator(t, srv.URL, client, "org-1", time.Hour)
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

func TestSessionValidator_Unauthenticated_Unhealthy(t *testing.T) {
	stub := &crlStub{list: func(*apiv1.ListRevokedSessionsRequest, http.Header) (*apiv1.ListRevokedSessionsResponse, error) {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}}
	srv := newCRLServer(t, stub)

	sv := newValidator(t, srv.URL, srv.Client(), "org-1", time.Hour)
	startOnce(t, sv)

	if sv.Healthy() {
		t.Error("Healthy() = true after unauthenticated refresh, want false")
	}
	if err := sv.LastRefreshError(); err == nil {
		t.Error("LastRefreshError() = nil after unauthenticated refresh, want error")
	} else if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("LastRefreshError() code = %v, want CodeUnauthenticated", connect.CodeOf(err))
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

	sv := newValidator(t, url, nil, "org-1", time.Hour)
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
	stub := &crlStub{list: func(*apiv1.ListRevokedSessionsRequest, http.Header) (*apiv1.ListRevokedSessionsResponse, error) {
		if fail.Load() {
			return nil, connect.NewError(connect.CodeInternal, nil)
		}
		return &apiv1.ListRevokedSessionsResponse{RevokedSessionIds: []string{"jti-x"}}, nil
	}}
	srv := newCRLServer(t, stub)

	// Short poll interval so the recovery refresh happens quickly.
	sv := newValidator(t, srv.URL, srv.Client(), "org-1", 20*time.Millisecond)
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
