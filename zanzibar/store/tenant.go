package store

import "context"

// tenantCtxKey is the context key for overriding the tenant ID on a per-request basis.
type tenantCtxKey struct{}

// ContextWithTenant returns a context that overrides the store's default tenant ID.
// This enables multi-tenant authorization -- the access handler injects the resolved
// tenant ID so tuples are scoped to the correct org.
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenantID)
}

// TenantFromContext returns the tenant ID from context, or empty string if not set.
func TenantFromContext(ctx context.Context) string {
	if t, ok := ctx.Value(tenantCtxKey{}).(string); ok && t != "" {
		return t
	}
	return ""
}
