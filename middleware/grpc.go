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
		// Fast path: upstream middleware already populated the principal.
		if _, ok := sdk.UserFromContext(ctx); ok {
			return handler(ctx, req)
		}

		scheme, token := extractGRPCAuthToken(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		if engine.RequireDPoP() && !strings.EqualFold(scheme, "DPoP") {
			return nil, status.Error(codes.Unauthenticated, "DPoP scheme required")
		}

		v := engine.Validator()
		if v == nil {
			// No validator configured -- fail closed. Accepting tokens
			// without validation would be fail-open authentication.
			engine.Logger().Error("gRPC auth interceptor rejecting request: no token validator configured (set Config.JWKSUrl)")
			return nil, status.Error(codes.Unauthenticated, "token validation not configured")
		}

		principal, identity, claims, _, err := v.ValidateToken(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Reject DPoP-bound tokens that arrived without upstream proof
		// validation. See ConnectInterceptor for the reasoning.
		if claims != nil && claims.Cnf != nil && claims.Cnf.JKT != "" && !sdk.IsDPoPVerified(ctx) {
			return nil, status.Error(codes.Unauthenticated,
				"DPoP-bound token requires HTTP middleware")
		}

		ctx = sdk.ContextWithUser(ctx, principal)
		ctx = sdk.ContextWithClaims(ctx, claims)
		if identity != nil {
			ctx = sdk.ContextWithIdentity(ctx, *identity)
		}
		return handler(ctx, req)
	}
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
