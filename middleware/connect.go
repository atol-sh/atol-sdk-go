package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"atol.sh/sdk-go"
)

// ConnectInterceptor returns a Connect-go interceptor that validates Bearer
// or DPoP tokens on unary and streaming handlers and sets authentication in
// context.
//
// DPoP note: Connect interceptors run after HTTP middleware and validate the
// token again. A DPoP-scheme or DPoP-bound token requires a proof verified
// by HTTPMiddleware for the same engine and token.
// This is because Connect's interceptor cannot reliably reconstruct
// the HTTP `htu` claim that the client signed the proof with.
func ConnectInterceptor(engine *sdk.Atol) connect.Interceptor {
	return &connectAuthInterceptor{engine: engine}
}

type connectAuthInterceptor struct{ engine *sdk.Atol }

func (i *connectAuthInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := i.authenticate(ctx, req.Header(), false)
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i *connectAuthInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i *connectAuthInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := i.authenticate(ctx, conn.RequestHeader(), true)
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

func (i *connectAuthInterceptor) authenticate(ctx context.Context, headers http.Header, streaming bool) (context.Context, error) {
	scheme, token := extractAuthTokenFromHeaders(headers)
	if token == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	if i.engine.RequireDPoP() && !strings.EqualFold(scheme, "DPoP") {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("DPoP scheme required"))
	}

	v := i.engine.Validator()
	if v == nil {
		i.engine.Logger().Error("connect auth interceptor rejecting request: no token validator configured (set Config.JWKSUrl)")
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("token validation not configured"))
	}
	principal, identity, claims, sessionID, err := v.ValidateToken(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	if streaming && claims != nil && (claims.TestUser || claims.AuthMethod == "test") {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("test-user tokens cannot open streams"))
	}
	if err := i.engine.CheckTokenSession(claims, sessionID); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	// Connect cannot reliably reconstruct the proof's htu across proxy
	// mounts. Require HTTPMiddleware to verify DPoP for this engine/token.
	clientIP, dpopVerified := verifiedHTTPAuth(ctx, i.engine, token)
	bound := claims != nil && claims.Cnf != nil && claims.Cnf.JKT != ""
	if (bound || strings.EqualFold(scheme, "DPoP")) && !dpopVerified {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("DPoP token requires HTTP middleware"))
	}
	principal.ClientIP = clientIP
	ctx = sdk.ContextWithUser(ctx, principal)
	ctx = sdk.ContextWithClaims(ctx, claims)
	if identity != nil {
		ctx = sdk.ContextWithIdentity(ctx, *identity)
	}
	return ctx, nil
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
