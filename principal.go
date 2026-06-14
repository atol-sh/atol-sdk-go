package sdk

import (
	"context"
	"time"

	atolidentity "atol.sh/sdk-go/identity"
)

type contextKey string

const (
	userContextKey         contextKey = "atol_user"
	identityContextKey     contextKey = "atol_identity"
	claimsContextKey       contextKey = "atol_claims"
	dpopVerifiedContextKey contextKey = "atol_dpop_verified"
)

// Principal represents an authenticated user in the request context.
type Principal struct {
	UserID        string
	IdentityID    string
	OrgID         string
	Email         string
	EmailVerified bool
	AuthMethod    string
	Roles         []string
	Plan          string
	MFAVerified   bool
	TrustDomain   string
	AuthTime      time.Time
	ClientIP      string
}

// Identity represents a scheme-specific identity linked to a principal.
type Identity struct {
	ID         string
	Scheme     string
	AuthMethod string
}

// UserFromContext extracts the authenticated principal from the context.
func UserFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(userContextKey).(*Principal)
	return p, ok
}

// ContextWithUser stores a principal in the context.
func ContextWithUser(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, userContextKey, p)
}

// IdentityFromContext extracts the scheme-specific identity from the context.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityContextKey).(Identity)
	return id, ok
}

// ContextWithIdentity stores a scheme-specific identity in the context.
func ContextWithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// ClaimsFromContext extracts the Atol JWT claims from the context.
func ClaimsFromContext(ctx context.Context) (*atolidentity.AtolClaims, bool) {
	c, ok := ctx.Value(claimsContextKey).(*atolidentity.AtolClaims)
	return c, ok
}

// ContextWithClaims stores Atol JWT claims in the context.
func ContextWithClaims(ctx context.Context, c *atolidentity.AtolClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey, c)
}

// ContextMarkDPoPVerified marks the request as having a valid DPoP proof
// attached that matched the access token's cnf.jkt binding. The HTTP
// middleware sets this after the proof validator succeeds so higher-level
// interceptors (Connect, gRPC) can trust that sender-constraint has
// already been enforced at the transport layer.
func ContextMarkDPoPVerified(ctx context.Context) context.Context {
	return context.WithValue(ctx, dpopVerifiedContextKey, true)
}

// IsDPoPVerified reports whether the request's DPoP proof was validated
// by an upstream middleware. Callers that consume DPoP-bound tokens
// without the HTTP middleware wrapper should treat false as a hard reject.
func IsDPoPVerified(ctx context.Context) bool {
	v, _ := ctx.Value(dpopVerifiedContextKey).(bool)
	return v
}
