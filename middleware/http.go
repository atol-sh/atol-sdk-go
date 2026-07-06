// Package middleware provides HTTP, Connect-go, and gRPC middleware
// for the Atol SDK. The middleware extracts tokens, validates them,
// runs authorization checks, and sets the principal in context.
package middleware

import (
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"atol.sh/sdk-go"
)

// HTTPMiddleware returns standard net/http middleware that:
//  1. Extracts the Bearer or DPoP token from the Authorization header.
//  2. Validates the token against JWKS (if configured).
//  3. For DPoP-scheme tokens, validates the `DPoP` proof header against
//     the token's `cnf.jkt` binding.
//  4. Sets the principal, identity, and claims in context.
//  5. Populates ClientIP from request headers.
func HTTPMiddleware(engine *sdk.Atol) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, token := extractAuthToken(r)
			if token == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if engine.RequireDPoP() && !strings.EqualFold(scheme, "DPoP") {
				// The resource server demands DPoP but the client presented a
				// bare Bearer -- emit an RFC 9449 section 7.1 challenge.
				sdk.WriteDPoPChallenge(w, nil)
				return
			}

			clientIP := extractClientIP(r)

			v := engine.Validator()
			if v == nil {
				// No validator configured -- fail closed. Accepting tokens
				// without validation would be fail-open authentication.
				engine.Logger().Error("auth middleware rejecting request: no token validator configured (set Config.JWKSUrl)",
					zap.String("path", r.URL.Path),
					zap.String("client_ip", clientIP))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			principal, identity, claims, sessionID, err := v.ValidateToken(r.Context(), token)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Check session revocation list (CRL).
			if sv := engine.SessionValidator(); sv != nil && sessionID != "" {
				if sv.IsRevoked(sessionID) {
					http.Error(w, "session revoked", http.StatusUnauthorized)
					return
				}
			}

			// Session-device drift: flag a token presented from a client whose
			// live signals diverge from the device bound to the session (e.g. a
			// replayed bearer token from curl). Non-blocking and best-effort.
			if dd := engine.DriftDetector(); dd != nil && sessionID != "" && principal != nil {
				dd.Inspect(r.Context(), principal.OrgID, sessionID, principal.UserID, r)
			}

			// DPoP sender-constraint enforcement.
			boundJKT := ""
			if claims != nil && claims.Cnf != nil {
				boundJKT = claims.Cnf.JKT
			}
			dpopOK := false
			if boundJKT != "" || strings.EqualFold(scheme, "DPoP") {
				// Either the token was issued with a binding (cnf.jkt set)
				// OR the client explicitly opted into DPoP scheme on the
				// wire. Both cases require a valid DPoP proof. Pass the
				// extracted access token so the proof's `ath` claim is
				// verified against it (RFC 9449 section 7.1).
				if _, derr := engine.DPoPValidator().Validate(r, boundJKT, token); derr != nil {
					// RFC 9449 section 7.1 challenge; never echo derr on the
					// wire (it embeds request/timing internals).
					sdk.WriteDPoPChallenge(w, nil, sdk.WithInvalidProofError())
					return
				}
				dpopOK = true
			}

			principal.ClientIP = clientIP

			ctx := sdk.ContextWithUser(r.Context(), principal)
			ctx = sdk.ContextWithClaims(ctx, claims)
			if identity != nil {
				ctx = sdk.ContextWithIdentity(ctx, *identity)
			}
			if dpopOK {
				ctx = sdk.ContextMarkDPoPVerified(ctx)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAuthToken parses the Authorization header and returns the scheme
// ("Bearer" or "DPoP") alongside the raw token. Unsupported schemes
// return ("", ""). Case-insensitive on the scheme per RFC 6750.
func extractAuthToken(r *http.Request) (scheme, token string) {
	auth := r.Header.Get("Authorization")
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

// extractBearerToken preserves the original signature for callers outside
// this package (and tests) that only care about the token value. It
// accepts both Bearer and DPoP schemes for backwards compatibility.
func extractBearerToken(r *http.Request) string {
	_, tok := extractAuthToken(r)
	return tok
}

// extractClientIP returns the client IP from X-Forwarded-For, X-Real-IP,
// or falls back to the remote address from the request.
func extractClientIP(r *http.Request) string {
	// Prefer X-Forwarded-For (first entry is the original client).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	// Fall back to X-Real-IP.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr, stripping port.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
