package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

type testTokenCRLHandler struct {
	apiv1connect.UnimplementedDPAgentServiceHandler
	ids       []string
	fail      bool
	exhausted bool
}

type streamDPAgentHandler struct {
	apiv1connect.UnimplementedDPAgentServiceHandler
	onStream func(context.Context)
}

func (h *streamDPAgentHandler) StreamMutations(
	ctx context.Context, _ *connect.Request[apiv1.StreamMutationsRequest],
	_ *connect.ServerStream[apiv1.StreamMutationsResponse],
) error {
	h.onStream(ctx)
	return nil
}

type testGRPCServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *testGRPCServerStream) Context() context.Context { return s.ctx }

func (h *testTokenCRLHandler) ListRevokedSessions(
	_ context.Context, req *connect.Request[apiv1.ListRevokedSessionsRequest],
) (*connect.Response[apiv1.ListRevokedSessionsResponse], error) {
	if req.Msg.GetOrgId() != "tenant-a" {
		return nil, connect.NewError(connect.CodePermissionDenied, nil)
	}
	if h.fail {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}
	if h.exhausted {
		return nil, connect.NewError(connect.CodeResourceExhausted, nil)
	}
	return connect.NewResponse(&apiv1.ListRevokedSessionsResponse{
		RevokedSessionIds: h.ids, AsOf: timestamppb.Now(),
	}), nil
}

func TestTokenSessionChecksAcrossMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ids        []string
		fail       bool
		exhausted  bool
		noCRL      bool
		testToken  bool
		wantAccept bool
	}{
		{"active test token", nil, false, false, false, true, true},
		{"revoked test token", []string{"session-a"}, false, false, false, true, false},
		{"failed CRL fetch", nil, true, false, false, true, false},
		{"no CRL configured", nil, false, false, true, true, false},
		{"revoked ordinary token", []string{"session-a"}, false, false, false, false, false},
		{"resource exhausted ordinary token", nil, false, true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := atoltest.NewTokenFactory(t)
			config := sdk.Config{
				StoreID: "tenant-a", Issuer: factory.Issuer(), JWKSUrl: factory.JWKSUrl(),
				Audience: "game", AllowTestTokens: true,
			}
			if !tc.noCRL {
				crl := &testTokenCRLHandler{ids: tc.ids, fail: tc.fail, exhausted: tc.exhausted}
				mux := http.NewServeMux()
				mux.Handle(apiv1connect.NewDPAgentServiceHandler(crl))
				server := httptest.NewServer(mux)
				t.Cleanup(server.Close)
				config.ControlPlaneURL = server.URL
			}
			engine, err := sdk.New(config)
			if err != nil {
				t.Fatalf("sdk.New: %v", err)
			}
			t.Cleanup(engine.Close)
			options := []atoltest.TokenOption{
				atoltest.WithOrgID("tenant-a"), atoltest.WithAudience("game"),
				atoltest.WithJTI("session-a"),
			}
			if tc.testToken {
				options = append(options, atoltest.WithTestUser(), atoltest.WithAuthMethod("test"))
			}
			token := factory.MintToken(options...)
			assertHTTPTokenSession(t, engine, token, tc.wantAccept)
			assertConnectTokenSession(t, engine, token, tc.wantAccept)
			assertGRPCTokenSession(t, engine, token, tc.wantAccept)
			assertConnectStreamTokenSession(t, engine, token, tc.wantAccept && !tc.testToken)
			assertGRPCStreamTokenSession(t, engine, token, tc.wantAccept && !tc.testToken)
		})
	}
}

func TestStreamInterceptorsRejectMissingAndInvalidTokens(t *testing.T) {
	factory := atoltest.NewTokenFactory(t)
	engine, err := sdk.New(sdk.Config{
		StoreID: "tenant-a", Issuer: factory.Issuer(), JWKSUrl: factory.JWKSUrl(), Audience: "game",
	})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	t.Cleanup(engine.Close)
	for _, token := range []string{"", "invalid-token"} {
		t.Run(token, func(t *testing.T) {
			assertConnectStreamTokenSession(t, engine, token, false)
			assertGRPCStreamTokenSession(t, engine, token, false)
		})
	}
}

func TestStreamInterceptorsRejectDPoPWithoutHTTPProof(t *testing.T) {
	factory := atoltest.NewTokenFactory(t)
	engine, err := sdk.New(sdk.Config{
		StoreID: "tenant-a", Issuer: factory.Issuer(), JWKSUrl: factory.JWKSUrl(),
		Audience: "game", RequireDPoP: true,
	})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	t.Cleanup(engine.Close)
	token := factory.MintToken(
		atoltest.WithOrgID("tenant-a"), atoltest.WithAudience("game"),
		atoltest.WithDPoPBinding("jkt-a"),
	)
	called := false
	path, endpoint := apiv1connect.NewDPAgentServiceHandler(
		&streamDPAgentHandler{onStream: func(context.Context) { called = true }},
		connect.WithInterceptors(ConnectInterceptor(engine)),
	)
	mux := http.NewServeMux()
	mux.Handle(path, endpoint)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := apiv1connect.NewDPAgentServiceClient(server.Client(), server.URL)
	req := connect.NewRequest(&apiv1.StreamMutationsRequest{OrgId: "tenant-a"})
	req.Header().Set("Authorization", "DPoP "+token)
	stream, err := client.StreamMutations(context.Background(), req)
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated || called {
		t.Errorf("Connect DPoP stream error/called = %v/%v, want unauthenticated/false", err, called)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "DPoP "+token))
	err = GRPCStreamInterceptor(engine)(nil, &testGRPCServerStream{ctx: ctx}, &grpc.StreamServerInfo{},
		func(_ interface{}, _ grpc.ServerStream) error {
			called = true
			return nil
		})
	if status.Code(err) != codes.Unauthenticated || called {
		t.Errorf("gRPC DPoP stream error/called = %v/%v, want unauthenticated/false", err, called)
	}
}

func TestInterceptorsDoNotTrustPrepopulatedPrincipal(t *testing.T) {
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	t.Cleanup(engine.Close)
	called := false
	path, endpoint := apiv1connect.NewDPAgentServiceHandler(
		&mockDPAgentHandler{onGetBootstrap: func(context.Context) { called = true }},
		connect.WithInterceptors(ConnectInterceptor(engine)),
	)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forged := sdk.ContextWithUser(r.Context(), &sdk.Principal{UserID: "forged", OrgID: "other-tenant"})
		endpoint.ServeHTTP(w, r.WithContext(forged))
	}))
	server := httptest.NewServer(mux)
	defer server.Close()
	client := apiv1connect.NewDPAgentServiceClient(server.Client(), server.URL)
	_, err = client.GetBootstrapSnapshot(context.Background(), connect.NewRequest(&apiv1.GetBootstrapSnapshotRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated || called {
		t.Errorf("prepopulated Connect principal error/called = %v/%v, want unauthenticated/false", err, called)
	}

	ctx := sdk.ContextWithUser(context.Background(), &sdk.Principal{UserID: "forged", OrgID: "other-tenant"})
	_, err = GRPCUnaryInterceptor(engine)(ctx, nil, &grpc.UnaryServerInfo{},
		func(context.Context, interface{}) (interface{}, error) {
			called = true
			return "ok", nil
		})
	if status.Code(err) != codes.Unauthenticated || called {
		t.Errorf("prepopulated gRPC principal error/called = %v/%v, want unauthenticated/false", err, called)
	}
}

func TestLayeredConnectPreservesVerifiedClientIP(t *testing.T) {
	factory := atoltest.NewTokenFactory(t)
	engine, err := sdk.New(sdk.Config{
		StoreID: "tenant-a", Issuer: factory.Issuer(), JWKSUrl: factory.JWKSUrl(), Audience: "game",
	})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	t.Cleanup(engine.Close)
	token := factory.MintToken(
		atoltest.WithOrgID("tenant-a"), atoltest.WithAudience("game"), atoltest.WithJTI("session-a"),
	)
	var clientIP string
	path, endpoint := apiv1connect.NewDPAgentServiceHandler(
		&mockDPAgentHandler{onGetBootstrap: func(ctx context.Context) {
			principal, _ := sdk.UserFromContext(ctx)
			clientIP = principal.ClientIP
		}},
		connect.WithInterceptors(ConnectInterceptor(engine)),
	)
	mux := http.NewServeMux()
	mux.Handle(path, HTTPMiddleware(engine)(endpoint))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := apiv1connect.NewDPAgentServiceClient(server.Client(), server.URL)
	req := connect.NewRequest(&apiv1.GetBootstrapSnapshotRequest{OrgId: "tenant-a"})
	req.Header().Set("Authorization", "Bearer "+token)
	req.Header().Set("X-Forwarded-For", "203.0.113.10")
	if _, err := client.GetBootstrapSnapshot(context.Background(), req); err != nil {
		t.Fatalf("layered Connect request: %v", err)
	}
	if clientIP == "203.0.113.10" || clientIP == "" {
		t.Errorf("ClientIP = %q, want verified HTTP client IP", clientIP)
	}

	ctx := sdk.ContextWithUser(context.Background(), &sdk.Principal{
		UserID: "forged", OrgID: "tenant-a", ClientIP: "198.51.100.99",
	})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	_, err = GRPCUnaryInterceptor(engine)(ctx, nil, &grpc.UnaryServerInfo{},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			principal, _ := sdk.UserFromContext(ctx)
			clientIP = principal.ClientIP
			return nil, nil
		})
	if err != nil {
		t.Fatalf("gRPC request: %v", err)
	}
	if clientIP != "" {
		t.Errorf("forged gRPC ClientIP = %q, want empty", clientIP)
	}
}

func TestInterceptorsRejectUnboundDPoPContextFlag(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bound       bool
		requireDPoP bool
	}{
		{"bound token", true, false},
		{"unbound token with DPoP required", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := atoltest.NewTokenFactory(t)
			engine, err := sdk.New(sdk.Config{
				StoreID: "tenant-a", Issuer: factory.Issuer(), JWKSUrl: factory.JWKSUrl(),
				Audience: "game", RequireDPoP: tc.requireDPoP,
			})
			if err != nil {
				t.Fatalf("sdk.New: %v", err)
			}
			t.Cleanup(engine.Close)
			options := []atoltest.TokenOption{
				atoltest.WithOrgID("tenant-a"), atoltest.WithAudience("game"),
			}
			if tc.bound {
				options = append(options, atoltest.WithDPoPBinding("jkt-a"))
			}
			token := factory.MintToken(options...)
			called := false
			path, endpoint := apiv1connect.NewDPAgentServiceHandler(
				&mockDPAgentHandler{onGetBootstrap: func(context.Context) { called = true }},
				connect.WithInterceptors(ConnectInterceptor(engine)),
			)
			mux := http.NewServeMux()
			mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				endpoint.ServeHTTP(w, r.WithContext(sdk.ContextMarkDPoPVerified(r.Context())))
			}))
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			client := apiv1connect.NewDPAgentServiceClient(server.Client(), server.URL)
			req := connect.NewRequest(&apiv1.GetBootstrapSnapshotRequest{OrgId: "tenant-a"})
			req.Header().Set("Authorization", "DPoP "+token)
			_, err = client.GetBootstrapSnapshot(context.Background(), req)
			if connect.CodeOf(err) != connect.CodeUnauthenticated || called {
				t.Errorf("Connect forged DPoP flag error/called = %v/%v, want unauthenticated/false", err, called)
			}

			ctx := sdk.ContextMarkDPoPVerified(context.Background())
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "DPoP "+token))
			_, err = GRPCUnaryInterceptor(engine)(ctx, nil, &grpc.UnaryServerInfo{},
				func(context.Context, interface{}) (interface{}, error) {
					called = true
					return nil, nil
				})
			if status.Code(err) != codes.Unauthenticated || called {
				t.Errorf("gRPC forged DPoP flag error/called = %v/%v, want unauthenticated/false", err, called)
			}
		})
	}
}

func assertHTTPTokenSession(t *testing.T, engine *sdk.Atol, token string, wantAccept bool) {
	t.Helper()
	called := false
	handler := HTTPMiddleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if called != wantAccept {
		t.Errorf("HTTP handler called = %v, want %v; status %d", called, wantAccept, response.Code)
	}
	if !wantAccept && response.Code != http.StatusUnauthorized {
		t.Errorf("HTTP status = %d, want 401", response.Code)
	}
}

func assertConnectTokenSession(t *testing.T, engine *sdk.Atol, token string, wantAccept bool) {
	t.Helper()
	called := false
	handler := &mockDPAgentHandler{onGetBootstrap: func(context.Context) { called = true }}
	path, endpoint := apiv1connect.NewDPAgentServiceHandler(
		handler, connect.WithInterceptors(ConnectInterceptor(engine)))
	mux := http.NewServeMux()
	mux.Handle(path, endpoint)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := apiv1connect.NewDPAgentServiceClient(server.Client(), server.URL)
	req := connect.NewRequest(&apiv1.GetBootstrapSnapshotRequest{OrgId: "tenant-a"})
	req.Header().Set("Authorization", "Bearer "+token)
	_, err := client.GetBootstrapSnapshot(context.Background(), req)
	if called != wantAccept {
		t.Errorf("Connect handler called = %v, want %v; error %v", called, wantAccept, err)
	}
	if wantAccept && err != nil {
		t.Errorf("Connect accepted token error = %v, want nil", err)
	}
	if !wantAccept && connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("Connect error = %v, want unauthenticated", err)
	}
}

func assertGRPCTokenSession(t *testing.T, engine *sdk.Atol, token string, wantAccept bool) {
	t.Helper()
	called := false
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	_, err := GRPCUnaryInterceptor(engine)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"},
		func(context.Context, interface{}) (interface{}, error) {
			called = true
			return "ok", nil
		})
	if called != wantAccept {
		t.Errorf("gRPC handler called = %v, want %v; error %v", called, wantAccept, err)
	}
	if wantAccept && err != nil {
		t.Errorf("gRPC accepted token error = %v, want nil", err)
	}
	if !wantAccept && status.Code(err) != codes.Unauthenticated {
		t.Errorf("gRPC error = %v, want unauthenticated", err)
	}
}

func assertConnectStreamTokenSession(t *testing.T, engine *sdk.Atol, token string, wantAccept bool) {
	t.Helper()
	called := false
	handler := &streamDPAgentHandler{onStream: func(ctx context.Context) {
		called = true
		if principal, ok := sdk.UserFromContext(ctx); !ok || principal == nil {
			t.Error("stream handler did not receive an authenticated principal")
		}
	}}
	path, endpoint := apiv1connect.NewDPAgentServiceHandler(
		handler, connect.WithInterceptors(ConnectInterceptor(engine)))
	mux := http.NewServeMux()
	mux.Handle(path, endpoint)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := apiv1connect.NewDPAgentServiceClient(server.Client(), server.URL)
	req := connect.NewRequest(&apiv1.StreamMutationsRequest{OrgId: "tenant-a"})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	stream, err := client.StreamMutations(context.Background(), req)
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if called != wantAccept {
		t.Errorf("Connect stream handler called = %v, want %v; error %v", called, wantAccept, err)
	}
	if wantAccept && err != nil {
		t.Errorf("Connect stream accepted token error = %v, want nil", err)
	}
	if !wantAccept && connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("Connect stream error = %v, want unauthenticated", err)
	}
}

func assertGRPCStreamTokenSession(t *testing.T, engine *sdk.Atol, token string, wantAccept bool) {
	t.Helper()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	called := false
	err := GRPCStreamInterceptor(engine)(nil, &testGRPCServerStream{ctx: ctx}, &grpc.StreamServerInfo{},
		func(_ interface{}, stream grpc.ServerStream) error {
			called = true
			if principal, ok := sdk.UserFromContext(stream.Context()); !ok || principal == nil {
				t.Error("gRPC stream handler did not receive an authenticated principal")
			}
			return nil
		})
	if called != wantAccept {
		t.Errorf("gRPC stream handler called = %v, want %v; error %v", called, wantAccept, err)
	}
	if wantAccept && err != nil {
		t.Errorf("gRPC stream accepted token error = %v, want nil", err)
	}
	if !wantAccept && status.Code(err) != codes.Unauthenticated {
		t.Errorf("gRPC stream error = %v, want unauthenticated", err)
	}
}
