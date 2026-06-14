package middleware

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"atol.sh/sdk-go"
)

func TestExtractGRPCToken(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "no metadata in context",
			ctx:  context.Background(),
			want: "",
		},
		{
			name: "metadata without authorization key",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("content-type", "application/grpc"),
			),
			want: "",
		},
		{
			name: "valid bearer token",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer mytoken"),
			),
			want: "mytoken",
		},
		{
			name: "bearer lowercase",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "bearer lowercase-tok"),
			),
			want: "lowercase-tok",
		},
		{
			name: "bearer mixed case",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "BEARER upper-tok"),
			),
			want: "upper-tok",
		},
		{
			name: "basic auth ignored",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Basic dXNlcjpwYXNz"),
			),
			want: "",
		},
		{
			name: "bearer without space",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer"),
			),
			want: "",
		},
		{
			name: "empty authorization value",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", ""),
			),
			want: "",
		},
		{
			name: "JWT-like token",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"),
			),
			want: "eyJhbGciOiJSUzI1NiJ9.payload.sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGRPCToken(tt.ctx)
			if got != tt.want {
				t.Errorf("extractGRPCToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGRPCUnaryInterceptor_NilValidator_FailsClosed pins the deny-by-default
// behavior: with no token validator configured, every RPC is rejected with
// codes.Unauthenticated -- the interceptor never fabricates a principal.
func TestGRPCUnaryInterceptor_NilValidator_FailsClosed(t *testing.T) {
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

	interceptor := GRPCUnaryInterceptor(engine)

	tests := []struct {
		name  string
		token string
	}{
		{name: "opaque token", token: "some-opaque-token"},
		{name: "JWT-like token", token: "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
		{name: "api key style token", token: "atol_key_abc123def456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer "+tt.token),
			)

			handlerCalled := false
			mockHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
				handlerCalled = true
				return "ok", nil
			}

			resp, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/TestMethod",
			}, mockHandler)
			if err == nil {
				t.Fatal("expected error with nil validator, got nil")
			}
			if status.Code(err) != codes.Unauthenticated {
				t.Errorf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
			}
			if resp != nil {
				t.Errorf("response = %v, want nil", resp)
			}
			if handlerCalled {
				t.Error("handler must not be called without a validator")
			}
		})
	}
}

func TestGRPCUnaryInterceptor_NoToken(t *testing.T) {
	t.Parallel()

	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	defer engine.Close()

	interceptor := GRPCUnaryInterceptor(engine)

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "no metadata",
			ctx:  context.Background(),
		},
		{
			name: "empty authorization",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", ""),
			),
		},
		{
			name: "basic auth instead of bearer",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Basic dXNlcjpwYXNz"),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := interceptor(tt.ctx, "test-request", &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/TestMethod",
			}, func(ctx context.Context, req interface{}) (interface{}, error) {
				t.Error("handler should not be called without token")
				return nil, nil
			})
			if err == nil {
				t.Fatal("expected error for missing token, got nil")
			}
		})
	}
}
