package sdk_test

import (
	"context"
	"testing"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/device"
	atolidentity "atol.sh/sdk-go/identity"
)

// TestUserFromContext_Populated verifies UserFromContext returns the principal
// that was stored in the context via ContextWithUser.
func TestUserFromContext_Populated(t *testing.T) {
	t.Parallel()

	want := &sdk.Principal{
		UserID:     "usr_abc",
		OrgID:      "org_acme",
		Email:      "a@b.c",
		AuthMethod: "passkey",
		Plan:       "pro",
		Roles:      []string{"admin"},
	}
	ctx := sdk.ContextWithUser(context.Background(), want)

	got, ok := sdk.UserFromContext(ctx)
	if !ok {
		t.Fatal("UserFromContext() ok = false, want true")
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID: got %q, want %q", got.UserID, want.UserID)
	}
	if got.OrgID != want.OrgID {
		t.Errorf("OrgID: got %q, want %q", got.OrgID, want.OrgID)
	}
	if got.Plan != want.Plan {
		t.Errorf("Plan: got %q, want %q", got.Plan, want.Plan)
	}
	if got.AuthMethod != want.AuthMethod {
		t.Errorf("AuthMethod: got %q, want %q", got.AuthMethod, want.AuthMethod)
	}
}

// TestUserFromContext_Empty verifies UserFromContext returns ok=false for an
// empty context so handlers can deny gracefully.
func TestUserFromContext_Empty(t *testing.T) {
	t.Parallel()

	p, ok := sdk.UserFromContext(context.Background())
	if ok {
		t.Errorf("UserFromContext(empty) ok = true, want false")
	}
	if p != nil {
		t.Errorf("UserFromContext(empty) principal = %v, want nil", p)
	}
}

// TestIdentityFromContext_Populated verifies the scheme-specific identity is
// retrievable after ContextWithIdentity.
func TestIdentityFromContext_Populated(t *testing.T) {
	t.Parallel()

	want := sdk.Identity{
		ID:         "oidc://accounts.google.com/123",
		Scheme:     "oidc",
		AuthMethod: "social",
	}
	ctx := sdk.ContextWithIdentity(context.Background(), want)

	got, ok := sdk.IdentityFromContext(ctx)
	if !ok {
		t.Fatal("IdentityFromContext() ok = false, want true")
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %q, want %q", got.ID, want.ID)
	}
	if got.Scheme != want.Scheme {
		t.Errorf("Scheme: got %q, want %q", got.Scheme, want.Scheme)
	}
}

// TestIdentityFromContext_Empty verifies the accessor returns ok=false on an
// empty context.
func TestIdentityFromContext_Empty(t *testing.T) {
	t.Parallel()

	_, ok := sdk.IdentityFromContext(context.Background())
	if ok {
		t.Error("IdentityFromContext(empty) ok = true, want false")
	}
}

// TestClaimsFromContext_Populated verifies JWT claims propagate through the
// request context.
func TestClaimsFromContext_Populated(t *testing.T) {
	t.Parallel()

	want := &atolidentity.AtolClaims{
		OrgID:      "org_acme",
		Plan:       "enterprise",
		Roles:      []string{"admin", "billing"},
		AuthMethod: "passkey",
	}
	ctx := sdk.ContextWithClaims(context.Background(), want)

	got, ok := sdk.ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("ClaimsFromContext() ok = false, want true")
	}
	if got.OrgID != want.OrgID {
		t.Errorf("OrgID: got %q, want %q", got.OrgID, want.OrgID)
	}
	if got.Plan != want.Plan {
		t.Errorf("Plan: got %q, want %q", got.Plan, want.Plan)
	}
	if len(got.Roles) != len(want.Roles) {
		t.Errorf("Roles len: got %d, want %d", len(got.Roles), len(want.Roles))
	}
}

// TestClaimsFromContext_Empty verifies the accessor returns ok=false on an
// empty context.
func TestClaimsFromContext_Empty(t *testing.T) {
	t.Parallel()

	_, ok := sdk.ClaimsFromContext(context.Background())
	if ok {
		t.Error("ClaimsFromContext(empty) ok = true, want false")
	}
}

// TestDeviceFromContext_Populated verifies the top-level sdk.DeviceFromContext
// re-export returns the device context stored via sdk.ContextWithDevice.
func TestDeviceFromContext_Populated(t *testing.T) {
	t.Parallel()

	want := &device.DeviceContext{
		DeviceID:   "dev_abc",
		Known:      true,
		Confidence: 0.97,
		Signals: &device.SmartSignals{
			Bot: false,
			VPN: true,
		},
	}
	ctx := sdk.ContextWithDevice(context.Background(), want)

	got := sdk.DeviceFromContext(ctx)
	if got == nil {
		t.Fatal("DeviceFromContext() = nil, want device context")
	}
	if got.DeviceID != want.DeviceID {
		t.Errorf("DeviceID: got %q, want %q", got.DeviceID, want.DeviceID)
	}
	if got.Known != want.Known {
		t.Errorf("Known: got %v, want %v", got.Known, want.Known)
	}
	if got.Confidence != want.Confidence {
		t.Errorf("Confidence: got %v, want %v", got.Confidence, want.Confidence)
	}
	if got.Signals == nil || got.Signals.VPN != true {
		t.Errorf("Signals.VPN: got %v, want true", got.Signals)
	}
}

// TestDeviceFromContext_Empty verifies DeviceFromContext returns nil (not
// panicking) when no device context has been populated.
func TestDeviceFromContext_Empty(t *testing.T) {
	t.Parallel()

	got := sdk.DeviceFromContext(context.Background())
	if got != nil {
		t.Errorf("DeviceFromContext(empty) = %v, want nil", got)
	}
}
