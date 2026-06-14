package atoltest

import (
	"net/http"

	sdk "atol.sh/sdk-go"
)

// AuthMiddleware returns HTTP middleware that injects a test principal into
// every request context. No JWT validation occurs. This replaces the
// hand-crafted injectAuth pattern commonly used in handler tests.
func AuthMiddleware(userID, email string, opts ...ContextOption) func(http.Handler) http.Handler {
	p := &sdk.Principal{
		UserID:     userID,
		Email:      email,
		AuthMethod: "test",
	}
	for _, o := range opts {
		o(p)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := sdk.ContextWithUser(r.Context(), p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ContextOption configures the principal injected by AuthMiddleware.
type ContextOption func(*sdk.Principal)

// WithMiddlewareOrg sets the organization ID on the middleware principal.
func WithMiddlewareOrg(orgID string) ContextOption {
	return func(p *sdk.Principal) { p.OrgID = orgID }
}

// WithMiddlewareRoles sets roles on the middleware principal.
func WithMiddlewareRoles(roles ...string) ContextOption {
	return func(p *sdk.Principal) { p.Roles = roles }
}

// WithMiddlewarePlan sets the plan on the middleware principal.
func WithMiddlewarePlan(plan string) ContextOption {
	return func(p *sdk.Principal) { p.Plan = plan }
}
