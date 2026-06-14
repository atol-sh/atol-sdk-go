package middleware

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"

	"atol.sh/sdk-go"
)

// ConnectInterceptor returns a Connect-go unary interceptor that validates
// Bearer or DPoP tokens and sets the principal, identity, and claims in
// context.
//
// DPoP note: Connect interceptors run after HTTP middleware, so if an
// upstream HTTPMiddleware already populated the principal (including
// proof validation), this interceptor is a cheap pass-through. When
// no HTTP middleware is wrapped, this interceptor still accepts the
// DPoP scheme for token extraction, but a DPoP-bound token (cnf.jkt
// present) is rejected unless the proof was already verified upstream.
// This is because Connect's interceptor cannot reliably reconstruct
// the HTTP `htu` claim that the client signed the proof with.
func ConnectInterceptor(engine *sdk.Atol) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Fast path: upstream HTTP middleware has already set the
			// principal on the context. Everything is done.
			if _, ok := sdk.UserFromContext(ctx); ok {
				return next(ctx, req)
			}

			scheme, token := extractAuthTokenFromHeaders(req.Header())
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, nil)
			}
			if engine.RequireDPoP() && !strings.EqualFold(scheme, "DPoP") {
				return nil, connect.NewError(connect.CodeUnauthenticated,
					errors.New("DPoP scheme required"))
			}

			v := engine.Validator()
			if v == nil {
				// No validator configured -- fail closed. Accepting tokens
				// without validation would be fail-open authentication.
				engine.Logger().Error("connect auth interceptor rejecting request: no token validator configured (set Config.JWKSUrl)")
				return nil, connect.NewError(connect.CodeUnauthenticated,
					errors.New("token validation not configured"))
			}

			principal, identity, claims, _, err := v.ValidateToken(ctx, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			// Reject DPoP-bound tokens that slipped in without HTTP-layer
			// proof validation. Doing the proof check here would require
			// reconstructing the htu from Connect's Spec, which is brittle
			// across reverse proxies and path mounts. Require HTTPMiddleware.
			if claims != nil && claims.Cnf != nil && claims.Cnf.JKT != "" && !sdk.IsDPoPVerified(ctx) {
				return nil, connect.NewError(connect.CodeUnauthenticated,
					errors.New("DPoP-bound token requires HTTP middleware"))
			}

			ctx = sdk.ContextWithUser(ctx, principal)
			ctx = sdk.ContextWithClaims(ctx, claims)
			if identity != nil {
				ctx = sdk.ContextWithIdentity(ctx, *identity)
			}
			return next(ctx, req)
		}
	}
}

func extractBearerFromHeaders(h interface{ Get(string) string }) string {
	_, tok := extractAuthTokenFromHeaders(h)
	return tok
}

// extractAuthTokenFromHeaders is the header-only equivalent of
// extractAuthToken. It accepts Bearer and DPoP schemes; anything else
// returns ("", "").
func extractAuthTokenFromHeaders(h interface{ Get(string) string }) (scheme, token string) {
	auth := h.Get("Authorization")
	if auth == "" {
		return "", ""
	}
	parts := strings.SplitN(auth, " ", 2)
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
