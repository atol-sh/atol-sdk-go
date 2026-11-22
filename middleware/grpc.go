package middleware

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"atol.sh/sdk-go"
)

// GRPCUnaryInterceptor returns a gRPC unary server interceptor that
// validates Bearer or DPoP tokens and sets the principal, identity,
// and claims in context. Full DPoP proof validation requires the HTTP
// middleware to run upstream (see ConnectInterceptor for details).
func GRPCUnaryInterceptor(engine *sdk.Atol) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var err error
		ctx, err = authenticateGRPC(ctx, engine, false)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// GRPCStreamInterceptor authenticates a gRPC stream before its handler runs.
// Register it alongside GRPCUnaryInterceptor to cover both RPC shapes.
func GRPCStreamInterceptor(engine *sdk.Atol) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authenticateGRPC(stream.Context(), engine, true)
		if err != nil {
			return err
		}
		return handler(srv, &authenticatedServerStream{ServerStream: stream, ctx: ctx})
	}
}

type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context { return s.ctx }

func authenticateGRPC(ctx context.Context, engine *sdk.Atol, streaming bool) (context.Context, error) {
	scheme, token := extractGRPCAuthToken(ctx)
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "missing bearer token")
	}
	if engine.RequireDPoP() && !strings.EqualFold(scheme, "DPoP") {
		return nil, status.Error(codes.Unauthenticated, "DPoP scheme required")
	}
	v := engine.Validator()
	if v == nil {
		engine.Logger().Error("gRPC auth interceptor rejecting request: no token validator configured (set Config.JWKSUrl)")
		return nil, status.Error(codes.Unauthenticated, "token validation not configured")
	}
	principal, identity, claims, sessionID, err := v.ValidateToken(ctx, token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if streaming && claims != nil && (claims.TestUser || claims.AuthMethod == "test") {
		return nil, status.Error(codes.Unauthenticated, "test-user tokens cannot open streams")
	}
	if err := engine.CheckTokenSession(claims, sessionID); err != nil {
		return nil, status.Error(codes.Unauthenticated, "session rejected")
	}
	clientIP, dpopVerified := verifiedHTTPAuth(ctx, engine, token)
	bound := claims != nil && claims.Cnf != nil && claims.Cnf.JKT != ""
	if (bound || strings.EqualFold(scheme, "DPoP")) && !dpopVerified {
		return nil, status.Error(codes.Unauthenticated, "DPoP token requires HTTP middleware")
	}
	principal.ClientIP = clientIP
	ctx = sdk.ContextWithUser(ctx, principal)
	ctx = sdk.ContextWithClaims(ctx, claims)
	if identity != nil {
		ctx = sdk.ContextWithIdentity(ctx, *identity)
	}
	return ctx, nil
}

func extractGRPCToken(ctx context.Context) string {
	_, tok := extractGRPCAuthToken(ctx)
	return tok
}

// extractGRPCAuthToken returns the Authorization scheme (Bearer or DPoP)
// and raw token from gRPC metadata. Unknown or missing schemes yield
// ("", "").
func extractGRPCAuthToken(ctx context.Context) (scheme, token string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}
	auths := md.Get("authorization")
	if len(auths) == 0 {
		return "", ""
	}
	parts := strings.SplitN(auths[0], " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	switch {
	case strings.EqualFold(parts[0], "Bearer"):
		return "Bearer", parts[1]
	case strings.EqualFold(parts[0], "DPoP"):
		return "DPoP", parts[1]
	default:
		return "", ""
	}
}
