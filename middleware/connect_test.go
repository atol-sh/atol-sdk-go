package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	"atol.sh/sdk-go"
	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// headerMap implements the interface { Get(string) string } used by
// extractBearerFromHeaders, matching http.Header's Get method.
type headerMap http.Header

func (h headerMap) Get(key string) string {
	return http.Header(h).Get(key)
}

func TestExtractBearerFromHeaders(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
		{
			name:   "valid bearer token",
			header: "Bearer token123",
			want:   "token123",
		},
		{
			name:   "basic auth ignored",
			header: "Basic xyz",
			want:   "",
		},
		{
			name:   "bearer without space",
			header: "Bearer",
			want:   "",
		},
		{
			name:   "bearer lowercase",
			header: "bearer mytoken",
			want:   "mytoken",
		},
		{
			name:   "bearer mixed case",
			header: "BEARER abc",
			want:   "abc",
		},
		{
			name:   "token with special characters",
			header: "Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature",
			want:   "eyJhbGciOiJSUzI1NiJ9.payload.signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := make(headerMap)
			if tt.header != "" {
				http.Header(h).Set("Authorization", tt.header)
			}
			got := extractBearerFromHeaders(h)
			if got != tt.want {
				t.Errorf("extractBearerFromHeaders() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConnectInterceptor_NilValidator_FailsClosed pins the deny-by-default
// behavior: with no token validator configured, every RPC is rejected with
// CodeUnauthenticated -- the interceptor never fabricates a principal.
func TestConnectInterceptor_NilValidator_FailsClosed(t *testing.T) {
	t.Parallel()

	// Create an Atol instance with no JWKS URL so the validator is nil.
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	defer engine.Close()

	if engine.Validator() != nil {
		t.Fatal("expected nil validator for empty config")
	}

	interceptor := ConnectInterceptor(engine)

	handlerCalled := false
	mockHandler := &mockDPAgentHandler{
		onGetBootstrap: func(ctx context.Context) {
			handlerCalled = true
		},
	}

	path, handler := apiv1connect.NewDPAgentServiceHandler(
		mockHandler,
		connect.WithInterceptors(interceptor),
	)

	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := apiv1connect.NewDPAgentServiceClient(http.DefaultClient, srv.URL)

	tests := []struct {
		name  string
		token string
	}{
		{name: "opaque token", token: "some-opaque-token"},
		{name: "JWT-like token", token: "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerCalled = false

			ctx := context.Background()
			req := connect.NewRequest(&apiv1.GetBootstrapSnapshotRequest{OrgId: "test-org"})
			req.Header().Set("Authorization", "Bearer "+tt.token)

			_, err := client.GetBootstrapSnapshot(ctx, req)
			if err == nil {
				t.Fatal("expected error with nil validator, got nil")
			}
			if connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), connect.CodeUnauthenticated)
			}
			if handlerCalled {
				t.Error("handler must not be called without a validator")
			}
		})
	}
}

// mockDPAgentHandler is a minimal DPAgentService handler for testing the interceptor.
type mockDPAgentHandler struct {
	apiv1connect.UnimplementedDPAgentServiceHandler
	onGetBootstrap func(ctx context.Context)
}

func (m *mockDPAgentHandler) GetBootstrapSnapshot(ctx context.Context, req *connect.Request[apiv1.GetBootstrapSnapshotRequest]) (*connect.Response[apiv1.GetBootstrapSnapshotResponse], error) {
	if m.onGetBootstrap != nil {
		m.onGetBootstrap(ctx)
	}
	return connect.NewResponse(&apiv1.GetBootstrapSnapshotResponse{}), nil
}
