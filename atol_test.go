package sdk_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
	"atol.sh/sdk-go/device"
	atolidentity "atol.sh/sdk-go/identity"
	"atol.sh/sdk-go/zanzibar/model"
)

var testModel = []byte(`
types:
  user: {}
  org:
    relations:
      owner:
        types: [user]
      admin:
        types: [user]
      member:
        union: [owner, admin]
  document:
    relations:
      org:
        types: [org]
      owner:
        types: [user]
      editor:
        types: [user]
      viewer:
        union: [owner, editor]
      can_share:
        union: [owner]
`)

// TestNew_MinimalConfig verifies that New succeeds with an empty config
// and produces a usable engine without control plane, JWKS, or session
// validator.
func TestNew_MinimalConfig(t *testing.T) {
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	if engine.Validator() != nil {
		t.Error("Validator() should be nil without JWKSUrl")
	}
	if engine.SessionValidator() != nil {
		t.Error("SessionValidator() should be nil without ControlPlaneURL")
	}
	if engine.DecisionLogger() != nil {
		t.Error("DecisionLogger() should be nil without ControlPlaneURL")
	}
	if engine.ZanzibarEngine() == nil {
		t.Error("ZanzibarEngine() should never be nil")
	}
}

// TestNew_WithLocalOnly verifies that WithLocalOnly enables local
// GrantAccess/RevokeAccess.
func TestNew_WithLocalOnly(t *testing.T) {
	engine, err := sdk.New(sdk.Config{}, sdk.WithLocalOnly())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	if err := engine.LoadModel(testModel); err != nil {
		t.Fatalf("LoadModel() error: %v", err)
	}

	ctx := context.Background()
	if err := engine.GrantAccess(ctx, "user:alice", "owner", "document:doc-1"); err != nil {
		t.Fatalf("GrantAccess() error: %v", err)
	}

	allowed, err := engine.Can(ctx, "user:alice", "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if !allowed {
		t.Error("Can() = false after GrantAccess, want true")
	}

	if err := engine.RevokeAccess(ctx, "user:alice", "owner", "document:doc-1"); err != nil {
		t.Fatalf("RevokeAccess() error: %v", err)
	}

	allowed, err = engine.Can(ctx, "user:alice", "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if allowed {
		t.Error("Can() = true after RevokeAccess, want false")
	}
}

// TestGrantAccess_NoControlPlane verifies that GrantAccess returns an error
// when no control plane is configured and local-only mode is not enabled.
func TestGrantAccess_NoControlPlane(t *testing.T) {
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	err = engine.GrantAccess(context.Background(), "user:x", "owner", "document:y")
	if err == nil {
		t.Error("GrantAccess() should fail without control plane or local-only")
	}

	err = engine.RevokeAccess(context.Background(), "user:x", "owner", "document:y")
	if err == nil {
		t.Error("RevokeAccess() should fail without control plane or local-only")
	}
}

// TestCheck_DenyByDefault verifies that Check returns false when there is
// no principal in context — the deny-by-default guarantee.
func TestCheck_DenyByDefault(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	// No principal in context → deny.
	allowed, err := engine.Check(context.Background(), "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if allowed {
		t.Error("Check() = true with no principal, want false (deny by default)")
	}
}

// TestCheck_WithPrincipal verifies that Check uses the principal from
// context and resolves against the Zanzibar store.
func TestCheck_WithPrincipal(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:remi", "editor", "document:doc-1")

	ctx := atoltest.Context().WithUser("remi").Build()

	// Direct relation.
	allowed, err := engine.Check(ctx, "editor", "document:doc-1")
	if err != nil {
		t.Fatalf("Check(editor) error: %v", err)
	}
	if !allowed {
		t.Error("Check(editor) = false, want true")
	}

	// Transitive via union (editor → viewer).
	allowed, err = engine.Check(ctx, "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("Check(viewer) error: %v", err)
	}
	if !allowed {
		t.Error("Check(viewer) = false, want true (editor → viewer)")
	}

	// Relation not held.
	allowed, err = engine.Check(ctx, "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("Check(owner) error: %v", err)
	}
	if allowed {
		t.Error("Check(owner) = true, want false")
	}
}

// TestCheckWithDetails verifies that CheckWithDetails returns a structured
// result with the correct allowed flag.
func TestCheckWithDetails(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:alice", "owner", "document:doc-1")

	ctx := atoltest.Context().WithUser("alice").Build()
	result, err := engine.CheckWithDetails(ctx, "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("CheckWithDetails() error: %v", err)
	}
	if !result.Allowed {
		t.Error("result.Allowed = false, want true")
	}

	// No principal → result indicates no_principal.
	result, err = engine.CheckWithDetails(context.Background(), "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("CheckWithDetails(no principal) error: %v", err)
	}
	if result.Allowed {
		t.Error("result.Allowed = true with no principal, want false")
	}
}

// TestCan_ExplicitUser verifies that Can does not require a principal in
// context — it takes the user explicitly.
func TestCan_ExplicitUser(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:bob", "editor", "document:doc-5")

	allowed, err := engine.Can(context.Background(), "user:bob", "editor", "document:doc-5")
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if !allowed {
		t.Error("Can() = false, want true")
	}
}

// TestCanWithDetails verifies the detailed result variant.
func TestCanWithDetails(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:alice", "owner", "org:acme")

	result, err := engine.CanWithDetails(context.Background(), "user:alice", "member", "org:acme")
	if err != nil {
		t.Fatalf("CanWithDetails() error: %v", err)
	}
	if !result.Allowed {
		t.Error("result.Allowed = false, want true (owner → member via union)")
	}
}

// TestWithContextTuples verifies that ephemeral tuples are considered for
// a single check and not persisted.
func TestWithContextTuples(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	ctx := context.Background()

	// With ephemeral tuple: allowed.
	allowed, err := engine.Can(ctx, "user:temp", "editor", "document:doc-1",
		sdk.WithContextTuples(model.Tuple{
			ObjectType: "document", ObjectID: "doc-1", Relation: "editor",
			UserType: "user", UserID: "temp",
		}),
	)
	if err != nil {
		t.Fatalf("Can(with context tuples) error: %v", err)
	}
	if !allowed {
		t.Error("Can(with context tuples) = false, want true")
	}

	// Without ephemeral tuple: denied (tuple was not persisted).
	allowed, err = engine.Can(ctx, "user:temp", "editor", "document:doc-1")
	if err != nil {
		t.Fatalf("Can(without context tuples) error: %v", err)
	}
	if allowed {
		t.Error("Can(without context tuples) = true, want false (context tuples are ephemeral)")
	}
}

// TestCheckDebug verifies the debug check returns meaningful diagnostic info.
func TestCheckDebug(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:alice", "owner", "document:doc-1")

	allowed, debug, err := engine.CheckDebug(context.Background(), "user:alice", "owner", "document:doc-1")
	if err != nil {
		t.Fatalf("CheckDebug() error: %v", err)
	}
	if !allowed {
		t.Errorf("CheckDebug() allowed = false, want true. Debug: %s", debug)
	}
	if debug == "" {
		t.Error("CheckDebug() debug string is empty")
	}
}

// TestAuthorize_DeniesWithoutPrincipal verifies that Authorize returns
// ErrAccessDenied when there is no principal in context.
func TestAuthorize_DeniesWithoutPrincipal(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	decision, err := engine.Authorize(context.Background(), "edit", "document:doc-1")
	if decision != nil {
		t.Error("decision should be nil when no principal")
	}
	if !errors.Is(err, sdk.ErrAccessDenied) {
		t.Errorf("err = %v, want ErrAccessDenied", err)
	}
}

// TestAuthorize_WithPrincipal verifies that Authorize constructs the full
// OPA input with principal attributes and evaluates correctly. Without a
// loaded OPA policy, it falls back to pure Zanzibar check.
func TestAuthorize_WithPrincipal(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:remi", "editor", "document:doc-1")

	ctx := atoltest.Context().
		WithUser("remi").
		WithOrg("acme").
		WithRoles("admin").
		WithPlan("pro").
		WithMFA().
		WithAuthMethod("passkey").
		WithIdentity("oidc://auth.atol.sh/remi", "oidc").
		Build()

	// With device context.
	ctx = device.ContextWithDevice(ctx, &device.DeviceContext{
		DeviceID:   "device:fp_abc",
		Known:      true,
		Confidence: 0.95,
	})

	decision, err := engine.Authorize(ctx, "editor", "document:doc-1")
	if err != nil {
		t.Fatalf("Authorize() error: %v", err)
	}
	if !decision.Allow {
		t.Errorf("decision.Allow = false, want true. Reason: %s", decision.Reason)
	}
	if decision.Err() != nil {
		t.Errorf("decision.Err() = %v, want nil", decision.Err())
	}
}

// TestDecision_Err verifies the Decision.Err helper.
func TestDecision_Err(t *testing.T) {
	allow := &sdk.Decision{Allow: true, Reason: "owner"}
	if allow.Err() != nil {
		t.Errorf("allow.Err() = %v, want nil", allow.Err())
	}

	deny := &sdk.Decision{Allow: false, Reason: "no relation"}
	if !errors.Is(deny.Err(), sdk.ErrAccessDenied) {
		t.Errorf("deny.Err() = %v, want ErrAccessDenied", deny.Err())
	}
}

// TestLoadModel verifies model loading and that it enables Check.
func TestLoadModel(t *testing.T) {
	engine, err := sdk.New(sdk.Config{}, sdk.WithLocalOnly())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	if err := engine.LoadModel(testModel); err != nil {
		t.Fatalf("LoadModel() error: %v", err)
	}

	if err := engine.ZanzibarEngine().WriteRawTuple(context.Background(), "user:x", "owner", "document:d"); err != nil {
		t.Fatalf("WriteRawTuple() error: %v", err)
	}
	allowed, err := engine.Can(context.Background(), "user:x", "owner", "document:d")
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if !allowed {
		t.Error("Can() = false after LoadModel + WriteTuple, want true")
	}
}

// TestDeviceConfig verifies the device config accessor.
func TestDeviceConfig(t *testing.T) {
	engine, err := sdk.New(sdk.Config{
		Device: device.Config{Enabled: true},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	cfg := engine.DeviceConfig()
	if !cfg.Enabled {
		t.Error("DeviceConfig().Enabled = false, want true")
	}
}

// TestBootstrap_NoControlPlane verifies that Bootstrap fails gracefully
// without a control plane URL.
func TestBootstrap_NoControlPlane(t *testing.T) {
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	err = engine.Bootstrap(context.Background())
	if err == nil {
		t.Error("Bootstrap() should fail without ControlPlaneURL")
	}
}

// TestBootstrap_NoStoreID verifies that Bootstrap fails without StoreID.
func TestBootstrap_NoStoreID(t *testing.T) {
	engine, err := sdk.New(sdk.Config{ControlPlaneURL: "http://localhost:9999"})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	err = engine.Bootstrap(context.Background())
	if err == nil {
		t.Error("Bootstrap() should fail without StoreID")
	}
}

// TestMaterializer verifies the materializer lifecycle through the
// public SDK API.
func TestMaterializer(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	engine.RegisterMaterializer("org-hierarchy", func(_ context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "owner", UserType: "user", UserID: "remi"},
		}, nil
	})

	if err := engine.Materialize(context.Background(), "org-hierarchy"); err != nil {
		t.Fatalf("Materialize() error: %v", err)
	}

	allowed, err := engine.Can(context.Background(), "user:remi", "owner", "org:acme")
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if !allowed {
		t.Error("Can() = false after materializer, want true")
	}
}

// TestTokenValidation_FullPipeline verifies the end-to-end token
// validation pipeline: mint → validate → extract principal fields.
func TestTokenValidation_FullPipeline(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	token := engine.Tokens().MintToken(
		atoltest.WithSubject("remi"),
		atoltest.WithOrgID("acme"),
		atoltest.WithRoles("admin"),
		atoltest.WithAuthMethod("passkey"),
	)

	v := engine.Validator()
	if v == nil {
		t.Fatal("Validator() is nil")
	}

	p, _, _, _, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if p.UserID != "remi" {
		t.Errorf("UserID = %q, want %q", p.UserID, "remi")
	}
	if p.OrgID != "acme" {
		t.Errorf("OrgID = %q, want %q", p.OrgID, "acme")
	}
}

// TestTokenValidation_InvalidToken verifies that an invalid token is rejected.
func TestTokenValidation_InvalidToken(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	_, _, _, _, err := engine.Validator().ValidateToken(context.Background(), "not.a.valid.jwt")
	if err == nil {
		t.Error("ValidateToken() should reject invalid token")
	}
}

// TestTokenValidation_ClockSkewLeeway verifies the 30s leeway: a token whose
// exp is a few seconds in the past is still accepted (absorbs NTP jitter and
// the small gap between silent renew and the request hitting the server), but
// a token expired by more than the leeway is rejected.
func TestTokenValidation_ClockSkewLeeway(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	// Expired by 5s -- within the 30s leeway, so must still validate.
	within := engine.Tokens().MintToken(
		atoltest.WithSubject("within-leeway"),
		atoltest.WithExpiry(-5*time.Second),
	)
	if _, _, _, _, err := engine.Validator().ValidateToken(context.Background(), within); err != nil {
		t.Errorf("token expired by 5s must be accepted (30s leeway), got %v", err)
	}

	// Expired by 2 minutes -- well past the 30s leeway, so must be rejected.
	beyond := engine.Tokens().MintToken(
		atoltest.WithSubject("beyond-leeway"),
		atoltest.WithExpiry(-2*time.Minute),
	)
	if _, _, _, _, err := engine.Validator().ValidateToken(context.Background(), beyond); err == nil {
		t.Error("token expired by 2m must be rejected, got nil error")
	}
}

// TestConfigDefaults verifies that Config.defaults() sets sane values.
func TestConfigDefaults(t *testing.T) {
	cfg := sdk.Config{ControlPlaneURL: "http://localhost:9080"}

	// Create engine to trigger defaults.
	engine, err := sdk.New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer engine.Close()

	// Validator should be created (JWKS URL derived from ControlPlaneURL).
	if engine.Validator() == nil {
		t.Error("Validator() should be non-nil when ControlPlaneURL is set")
	}
}

// TestClose_Idempotent verifies that Close can be called multiple times safely.
func TestClose_Idempotent(t *testing.T) {
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	engine.Close()
	engine.Close() // should not panic
}

// TestPrincipal_ContextRoundtrip verifies that all context helpers work correctly.
func TestPrincipal_ContextRoundtrip(t *testing.T) {
	p := &sdk.Principal{
		UserID:      "usr_123",
		OrgID:       "acme",
		Roles:       []string{"admin"},
		MFAVerified: true,
		AuthTime:    time.Now(),
	}

	ctx := sdk.ContextWithUser(context.Background(), p)
	got, ok := sdk.UserFromContext(ctx)
	if !ok {
		t.Fatal("UserFromContext() = false")
	}
	if got.UserID != "usr_123" {
		t.Errorf("UserID = %q, want %q", got.UserID, "usr_123")
	}

	// Identity roundtrip.
	id := sdk.Identity{ID: "oidc://x", Scheme: "oidc", AuthMethod: "passkey"}
	ctx = sdk.ContextWithIdentity(ctx, id)
	gotID, ok := sdk.IdentityFromContext(ctx)
	if !ok {
		t.Fatal("IdentityFromContext() = false")
	}
	if gotID.ID != "oidc://x" {
		t.Errorf("Identity.ID = %q, want %q", gotID.ID, "oidc://x")
	}

	// Claims roundtrip.
	claims := &atolidentity.AtolClaims{OrgID: "acme", Plan: "pro"}
	ctx = sdk.ContextWithClaims(ctx, claims)
	gotClaims, ok := sdk.ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("ClaimsFromContext() = false")
	}
	if gotClaims.OrgID != "acme" {
		t.Errorf("Claims.OrgID = %q, want %q", gotClaims.OrgID, "acme")
	}

	// Missing context returns false.
	_, ok = sdk.UserFromContext(context.Background())
	if ok {
		t.Error("UserFromContext(empty) = true, want false")
	}
	_, ok = sdk.ClaimsFromContext(context.Background())
	if ok {
		t.Error("ClaimsFromContext(empty) = true, want false")
	}
}

// TestMaterializeAll runs all registered materializers through the SDK.
func TestMaterializeAll(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	engine.RegisterMaterializer("teams", func(_ context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "org", ObjectID: "acme", Relation: "admin", UserType: "user", UserID: "alice"},
		}, nil
	})
	engine.RegisterMaterializer("docs", func(_ context.Context) ([]model.Tuple, error) {
		return []model.Tuple{
			{ObjectType: "document", ObjectID: "doc-1", Relation: "owner", UserType: "user", UserID: "bob"},
		}, nil
	})

	if err := engine.MaterializeAll(context.Background()); err != nil {
		t.Fatalf("MaterializeAll() error: %v", err)
	}

	allowed, _ := engine.Can(context.Background(), "user:alice", "admin", "org:acme")
	if !allowed {
		t.Error("alice should be admin of org:acme after materialization")
	}
	allowed, _ = engine.Can(context.Background(), "user:bob", "owner", "document:doc-1")
	if !allowed {
		t.Error("bob should be owner of document:doc-1 after materialization")
	}
}

// TestSessionValidator_IsRevoked tests session revocation checks directly.
func TestSessionValidator_IsRevoked(t *testing.T) {
	sv := sdk.NewSessionValidator("http://localhost:0", "test-org", 1*time.Hour, nil, nil)
	// Don't start — we don't need polling, just the IsRevoked check.

	// Empty revocation list — nothing is revoked.
	if sv.IsRevoked("session-1") {
		t.Error("IsRevoked(session-1) = true, want false (empty CRL)")
	}

	// Empty session ID — never revoked.
	if sv.IsRevoked("") {
		t.Error("IsRevoked('') = true, want false")
	}
}
