package middleware

import (
	"context"
	"crypto/sha256"

	sdk "atol.sh/sdk-go"
)

type httpAuthContextKey struct{}

type httpAuthContext struct {
	engine       *sdk.Atol
	tokenHash    [sha256.Size]byte
	clientIP     string
	dpopVerified bool
}

func markHTTPAuth(ctx context.Context, engine *sdk.Atol, token, clientIP string, dpopVerified bool) context.Context {
	return context.WithValue(ctx, httpAuthContextKey{}, httpAuthContext{
		engine: engine, tokenHash: sha256.Sum256([]byte(token)), clientIP: clientIP, dpopVerified: dpopVerified,
	})
}

func verifiedHTTPAuth(ctx context.Context, engine *sdk.Atol, token string) (string, bool) {
	marker, ok := ctx.Value(httpAuthContextKey{}).(httpAuthContext)
	if !ok || marker.engine != engine || marker.tokenHash != sha256.Sum256([]byte(token)) {
		return "", false
	}
	return marker.clientIP, marker.dpopVerified
}
