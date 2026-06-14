package atoltest

import (
	"context"
	"time"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/device"
)

// ContextBuilder constructs authenticated request contexts for testing.
// It replaces hand-crafted ContextWithTestUser helpers.
type ContextBuilder struct {
	parent    context.Context
	principal *sdk.Principal
	identity  *sdk.Identity
	device    *device.DeviceContext
}

// Context starts building a test context with an empty principal.
func Context() *ContextBuilder {
	return &ContextBuilder{
		parent:    context.Background(),
		principal: &sdk.Principal{AuthMethod: "test"},
	}
}

// FromContext starts building from an existing context.
func FromContext(ctx context.Context) *ContextBuilder {
	return &ContextBuilder{
		parent:    ctx,
		principal: &sdk.Principal{AuthMethod: "test"},
	}
}

// WithUser sets the user ID (the JWT subject equivalent).
func (b *ContextBuilder) WithUser(userID string) *ContextBuilder {
	b.principal.UserID = userID
	return b
}

// WithEmail sets the user's email address.
func (b *ContextBuilder) WithEmail(email string) *ContextBuilder {
	b.principal.Email = email
	return b
}

// WithOrg sets the organization ID.
func (b *ContextBuilder) WithOrg(orgID string) *ContextBuilder {
	b.principal.OrgID = orgID
	return b
}

// WithRoles sets the user's roles.
func (b *ContextBuilder) WithRoles(roles ...string) *ContextBuilder {
	b.principal.Roles = roles
	return b
}

// WithPlan sets the subscription plan.
func (b *ContextBuilder) WithPlan(plan string) *ContextBuilder {
	b.principal.Plan = plan
	return b
}

// WithAuthMethod sets the authentication method.
func (b *ContextBuilder) WithAuthMethod(method string) *ContextBuilder {
	b.principal.AuthMethod = method
	return b
}

// WithMFA marks the user as MFA-verified.
func (b *ContextBuilder) WithMFA() *ContextBuilder {
	b.principal.MFAVerified = true
	return b
}

// WithIdentity sets the scheme-specific identity.
func (b *ContextBuilder) WithIdentity(id, scheme string) *ContextBuilder {
	b.identity = &sdk.Identity{
		ID:     id,
		Scheme: scheme,
	}
	return b
}

// WithTrustDomain sets the SPIFFE trust domain.
func (b *ContextBuilder) WithTrustDomain(domain string) *ContextBuilder {
	b.principal.TrustDomain = domain
	return b
}

// WithClientIP sets the client IP address.
func (b *ContextBuilder) WithClientIP(ip string) *ContextBuilder {
	b.principal.ClientIP = ip
	return b
}

// WithAuthTime sets when authentication occurred.
func (b *ContextBuilder) WithAuthTime(t time.Time) *ContextBuilder {
	b.principal.AuthTime = t
	return b
}

// WithDevice sets the device intelligence context.
func (b *ContextBuilder) WithDevice(dc *device.DeviceContext) *ContextBuilder {
	b.device = dc
	return b
}

// Build returns the fully constructed context with principal (and optionally
// identity and device) set.
func (b *ContextBuilder) Build() context.Context {
	ctx := sdk.ContextWithUser(b.parent, b.principal)
	if b.identity != nil {
		ctx = sdk.ContextWithIdentity(ctx, *b.identity)
	}
	if b.device != nil {
		ctx = device.ContextWithDevice(ctx, b.device)
	}
	return ctx
}
