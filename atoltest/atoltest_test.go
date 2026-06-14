package atoltest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
	"atol.sh/sdk-go/device"
	atolmw "atol.sh/sdk-go/middleware"
)

var testModel = []byte(`
types:
  user: {}
  document:
    relations:
      owner:
        types: [user]
      editor:
        types: [user]
      viewer:
        union: [owner, editor]
`)

// TestCheckWithUnionTraversal verifies that the test engine performs real
// Zanzibar graph traversal. A union rule (viewer = owner | editor) must
// resolve transitively — this catches bugs where the model isn't loaded
// or tuples aren't written correctly.
func TestCheckWithUnionTraversal(t *testing.T) {
	engine := atoltest.NewEngine(t,
		atoltest.WithModel(testModel),
		atoltest.WithTuples(
			atoltest.Tuple{User: "user:alice", Relation: "owner", Object: "document:doc-1"},
			atoltest.Tuple{User: "user:bob", Relation: "editor", Object: "document:doc-1"},
		),
	)

	tests := []struct {
		user, relation, object string
		want                   bool
	}{
		{"alice", "owner", "document:doc-1", true},
		{"alice", "viewer", "document:doc-1", true}, // owner → viewer via union
		{"bob", "editor", "document:doc-1", true},
		{"bob", "viewer", "document:doc-1", true},  // editor → viewer via union
		{"bob", "owner", "document:doc-1", false},  // editor ≠ owner
		{"eve", "viewer", "document:doc-1", false}, // no tuples at all
	}

	for _, tt := range tests {
		ctx := atoltest.Context().WithUser(tt.user).Build()
		got, err := engine.Check(ctx, tt.relation, tt.object)
		if err != nil {
			t.Fatalf("Check(%s, %s, %s) error: %v", tt.user, tt.relation, tt.object, err)
		}
		if got != tt.want {
			t.Errorf("Check(%s, %s, %s) = %v, want %v", tt.user, tt.relation, tt.object, got, tt.want)
		}
	}
}

// TestGrantAccessRevokeAccess_LocalOnly verifies that GrantAccess/RevokeAccess
// work without a control plane. This is the whole point of WithLocalOnly() —
// customers shouldn't need WriteRawTuple in tests.
func TestGrantAccessRevokeAccess_LocalOnly(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	ctx := context.Background()

	if err := engine.GrantAccess(ctx, "user:alice", "owner", "document:doc-99"); err != nil {
		t.Fatalf("GrantAccess() error: %v", err)
	}

	allowed, err := engine.Can(ctx, "user:alice", "owner", "document:doc-99")
	if err != nil {
		t.Fatalf("Can() after grant: %v", err)
	}
	if !allowed {
		t.Error("Can() = false after GrantAccess, want true")
	}

	if err := engine.RevokeAccess(ctx, "user:alice", "owner", "document:doc-99"); err != nil {
		t.Fatalf("RevokeAccess() error: %v", err)
	}

	allowed, err = engine.Can(ctx, "user:alice", "owner", "document:doc-99")
	if err != nil {
		t.Fatalf("Can() after revoke: %v", err)
	}
	if allowed {
		t.Error("Can() = true after RevokeAccess, want false")
	}
}

// TestGrantAll verifies bulk tuple population — the main use case for
// replacing 261-line TestMain boilerplate.
func TestGrantAll(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	engine.GrantAll([]atoltest.Tuple{
		{User: "user:a", Relation: "owner", Object: "document:d1"},
		{User: "user:b", Relation: "editor", Object: "document:d1"},
		{User: "user:c", Relation: "editor", Object: "document:d2"},
	})

	tests := []struct {
		user, relation, object string
		want                   bool
	}{
		{"user:a", "owner", "document:d1", true},
		{"user:b", "editor", "document:d1", true},
		{"user:c", "editor", "document:d2", true},
		{"user:a", "editor", "document:d2", false}, // no cross-contamination
	}

	for _, tt := range tests {
		got, err := engine.Can(context.Background(), tt.user, tt.relation, tt.object)
		if err != nil {
			t.Fatalf("Can(%s, %s, %s) error: %v", tt.user, tt.relation, tt.object, err)
		}
		if got != tt.want {
			t.Errorf("Can(%s, %s, %s) = %v, want %v", tt.user, tt.relation, tt.object, got, tt.want)
		}
	}

	// Revoke one and verify it's gone while others remain.
	engine.Revoke("user:b", "editor", "document:d1")
	got, _ := engine.Can(context.Background(), "user:b", "editor", "document:d1")
	if got {
		t.Error("Can(user:b, editor, d1) = true after Revoke, want false")
	}
	got, _ = engine.Can(context.Background(), "user:a", "owner", "document:d1")
	if !got {
		t.Error("Can(user:a, owner, d1) = false, want true (unrevoked)")
	}
}

// TestWithModelFile loads the model from disk — the intended replacement
// for pasting 80 lines of YAML into TestMain.
func TestWithModelFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "model.yaml")
	if err := os.WriteFile(path, testModel, 0o644); err != nil {
		t.Fatalf("write model file: %v", err)
	}

	engine := atoltest.NewEngine(t, atoltest.WithModelFile(path))
	engine.Grant("user:remi", "editor", "document:doc-1")

	ctx := atoltest.Context().WithUser("remi").Build()
	allowed, err := engine.Check(ctx, "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !allowed {
		t.Error("Check() = false, want true (editor → viewer via union)")
	}
}

// TestTokenClaimsRoundtrip mints a token with every claim type, validates it
// with the real SDK TokenValidator, and verifies all fields survive the
// roundtrip. This is the critical path — if any claim's JSON tag is wrong
// or the JWT structure is off, the SDK will reject the token.
func TestTokenClaimsRoundtrip(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	authTime := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)

	token := engine.Tokens().MintToken(
		atoltest.WithSubject("remi"),
		atoltest.WithEmail("user@example.com"),
		atoltest.WithOrgID("acme"),
		atoltest.WithRoles("admin", "editor"),
		atoltest.WithPlan("enterprise"),
		atoltest.WithMFA(),
		atoltest.WithAuthMethod("passkey"),
		atoltest.WithIdentity("oidc://auth.atol.sh/abc", "oidc"),
		atoltest.WithTrustDomain("acme.atol.sh"),
		atoltest.WithJTI("session-42"),
		atoltest.WithAuthTime(authTime),
	)

	principal, identity, _, sessionID, err := engine.Validator().ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}

	// Verify every Principal field.
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"UserID", principal.UserID, "remi"},
		{"OrgID", principal.OrgID, "acme"},
		{"Plan", principal.Plan, "enterprise"},
		{"MFAVerified", principal.MFAVerified, true},
		{"AuthMethod", principal.AuthMethod, "passkey"},
		{"TrustDomain", principal.TrustDomain, "acme.atol.sh"},
		{"AuthTime", principal.AuthTime.Unix(), authTime.Unix()},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("Principal.%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if len(principal.Roles) != 2 || principal.Roles[0] != "admin" || principal.Roles[1] != "editor" {
		t.Errorf("Roles = %v, want [admin editor]", principal.Roles)
	}

	// Verify Identity roundtrip.
	if identity.ID != "oidc://auth.atol.sh/abc" {
		t.Errorf("Identity.ID = %q, want %q", identity.ID, "oidc://auth.atol.sh/abc")
	}
	if identity.Scheme != "oidc" {
		t.Errorf("Identity.Scheme = %q, want %q", identity.Scheme, "oidc")
	}

	// Verify JTI roundtrip.
	if sessionID != "session-42" {
		t.Errorf("sessionID = %q, want %q", sessionID, "session-42")
	}
}

// TestExpiredTokenRejected verifies that the SDK's real TokenValidator
// correctly rejects expired test tokens.
func TestExpiredTokenRejected(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	token := engine.Tokens().MintToken(
		atoltest.WithSubject("expired-user"),
		atoltest.WithExpiry(-1*time.Hour), // already expired
	)

	_, _, _, _, err := engine.Validator().ValidateToken(context.Background(), token)
	if err == nil {
		t.Fatal("ValidateToken() should reject expired token")
	}
}

// TestAudienceValidation verifies that audience mismatch is caught.
// The SDK validator checks aud when configured — this ensures test tokens
// include the audience claim and the engine enforces it.
func TestAudienceValidation(t *testing.T) {
	engine := atoltest.NewEngine(t,
		atoltest.WithModel(testModel),
		atoltest.WithTestAudience("https://api.example.com"),
	)

	// Token with matching audience should pass.
	goodToken := engine.Tokens().MintToken(
		atoltest.WithSubject("alice"),
		atoltest.WithAudience("https://api.example.com"),
	)
	p, _, _, _, err := engine.Validator().ValidateToken(context.Background(), goodToken)
	if err != nil {
		t.Fatalf("ValidateToken(matching aud) error: %v", err)
	}
	if p.UserID != "alice" {
		t.Errorf("UserID = %q, want %q", p.UserID, "alice")
	}

	// Token without audience should be rejected.
	badToken := engine.Tokens().MintToken(atoltest.WithSubject("bob"))
	_, _, _, _, err = engine.Validator().ValidateToken(context.Background(), badToken)
	if err == nil {
		t.Fatal("ValidateToken(no aud) should reject when engine requires audience")
	}
}

// TestContextBuilder_FullPrincipal builds a context with every field and
// verifies they survive through the SDK's context helpers. This covers
// FromContext, WithIdentity, WithDevice, WithAuthMethod, WithClientIP,
// WithAuthTime, WithTrustDomain.
func TestContextBuilder_FullPrincipal(t *testing.T) {
	parent := context.WithValue(context.Background(), contextKeyForTest("request_id"), "req-123")
	authTime := time.Now().Add(-5 * time.Minute)

	dc := &device.DeviceContext{
		DeviceID:   "device:fp_abc",
		Known:      true,
		Confidence: 0.95,
	}

	ctx := atoltest.FromContext(parent).
		WithUser("usr_123").
		WithEmail("test@example.com").
		WithOrg("acme").
		WithRoles("admin", "editor").
		WithPlan("pro").
		WithAuthMethod("passkey").
		WithMFA().
		WithIdentity("oidc://auth.atol.sh/abc", "oidc").
		WithTrustDomain("acme.atol.sh").
		WithClientIP("10.0.1.42").
		WithAuthTime(authTime).
		WithDevice(dc).
		Build()

	// Parent context value should be preserved.
	if ctx.Value(contextKeyForTest("request_id")) != "req-123" {
		t.Error("parent context value lost")
	}

	// Verify Principal.
	p, ok := sdk.UserFromContext(ctx)
	if !ok {
		t.Fatal("UserFromContext() returned false")
	}
	if p.UserID != "usr_123" {
		t.Errorf("UserID = %q, want %q", p.UserID, "usr_123")
	}
	if p.AuthMethod != "passkey" {
		t.Errorf("AuthMethod = %q, want %q", p.AuthMethod, "passkey")
	}
	if p.ClientIP != "10.0.1.42" {
		t.Errorf("ClientIP = %q, want %q", p.ClientIP, "10.0.1.42")
	}
	if p.TrustDomain != "acme.atol.sh" {
		t.Errorf("TrustDomain = %q, want %q", p.TrustDomain, "acme.atol.sh")
	}
	if p.AuthTime.Unix() != authTime.Unix() {
		t.Errorf("AuthTime = %v, want %v", p.AuthTime, authTime)
	}

	// Verify Identity.
	id, ok := sdk.IdentityFromContext(ctx)
	if !ok {
		t.Fatal("IdentityFromContext() returned false")
	}
	if id.ID != "oidc://auth.atol.sh/abc" {
		t.Errorf("Identity.ID = %q, want %q", id.ID, "oidc://auth.atol.sh/abc")
	}

	// Verify Device.
	d := device.DeviceFromContext(ctx)
	if d == nil {
		t.Fatal("DeviceFromContext() returned nil")
	}
	if d.DeviceID != "device:fp_abc" {
		t.Errorf("DeviceID = %q, want %q", d.DeviceID, "device:fp_abc")
	}
}

type contextKeyForTest string

// TestAuthMiddleware_WithPlan verifies the middleware injects all configured
// Principal fields.
func TestAuthMiddleware_WithPlan(t *testing.T) {
	mw := atoltest.AuthMiddleware("usr_1", "usr@example.com",
		atoltest.WithMiddlewareOrg("acme"),
		atoltest.WithMiddlewareRoles("admin"),
		atoltest.WithMiddlewarePlan("enterprise"),
	)

	var captured *sdk.Principal
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		p, _ := sdk.UserFromContext(r.Context())
		captured = p
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	if captured == nil {
		t.Fatal("principal not set")
	}
	if captured.Plan != "enterprise" {
		t.Errorf("Plan = %q, want %q", captured.Plan, "enterprise")
	}
}

// TestEndToEnd_RealTokenThroughMiddleware is the critical integration test:
// mint a real JWT, send it through the SDK's actual HTTP middleware, and
// check authorization. This verifies the entire stack: JWKS → token
// validation → context injection → Zanzibar check.
func TestEndToEnd_RealTokenThroughMiddleware(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	engine.Grant("user:remi", "owner", "document:doc-123")

	token := engine.Tokens().MintToken(atoltest.WithSubject("remi"))

	handler := atolmw.HTTPMiddleware(engine.Atol)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, err := engine.Check(r.Context(), "owner", "document:doc-123")
			if err != nil || !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	)

	// Valid token → 200.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("valid token: status = %d, want 200", w.Code)
	}

	// No token → 401.
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}
}

// TestMockOIDCServer_TokenValidatesWithEngine verifies the full E2E flow
// that replaces the Node.js mock-auth server: POST /oauth/token → get JWT
// → validate with a real SDK engine. This is what Cypress E2E tests do.
func TestMockOIDCServer_TokenValidatesWithEngine(t *testing.T) {
	srv := atoltest.NewMockOIDCServer(t)

	// Create an engine configured to trust this server.
	engine := atoltest.NewEngine(t,
		atoltest.WithModel(testModel),
		atoltest.WithTokenFactory(srv.TokenFactory()),
	)

	// Mint a token via the HTTP endpoint (like Cypress would).
	resp, err := http.Post(srv.URL()+"/oauth/token", "application/json",
		strings.NewReader(`{"sub":"cypress-user","email":"e2e@test.example.com","org_id":"acme","roles":["admin"]}`))
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", body.TokenType)
	}
	if body.ExpiresIn == 0 {
		t.Error("expires_in = 0, want > 0")
	}

	// Validate the HTTP-minted token with the SDK's real validator.
	p, _, _, _, err := engine.Validator().ValidateToken(context.Background(), body.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}
	if p.UserID != "cypress-user" {
		t.Errorf("UserID = %q, want %q", p.UserID, "cypress-user")
	}
	if p.OrgID != "acme" {
		t.Errorf("OrgID = %q, want %q", p.OrgID, "acme")
	}
}

// TestMockOIDCServer_InvalidJSON verifies the token endpoint rejects
// malformed input instead of silently accepting it.
func TestMockOIDCServer_InvalidJSON(t *testing.T) {
	srv := atoltest.NewMockOIDCServer(t)

	resp, err := http.Post(srv.URL()+"/oauth/token", "application/json",
		strings.NewReader(`{invalid json`))
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestMockOIDCServer_EmptyBody verifies default values work when no body
// is sent — the server should mint a token with defaults.
func TestMockOIDCServer_EmptyBody(t *testing.T) {
	srv := atoltest.NewMockOIDCServer(t)

	resp, err := http.Post(srv.URL()+"/oauth/token", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.AccessToken == "" {
		t.Error("access_token is empty for default body")
	}
}

// TestMockOIDCServer_Discovery verifies the OIDC discovery document points
// to the correct server URL.
func TestMockOIDCServer_Discovery(t *testing.T) {
	srv := atoltest.NewMockOIDCServer(t)

	resp, err := http.Get(srv.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var doc map[string]any
	json.NewDecoder(resp.Body).Decode(&doc)

	if doc["issuer"] != srv.URL() {
		t.Errorf("issuer = %q, want %q", doc["issuer"], srv.URL())
	}
	jwksURI, _ := doc["jwks_uri"].(string)
	if !strings.HasSuffix(jwksURI, "/.well-known/jwks.json") {
		t.Errorf("jwks_uri = %q, want suffix /.well-known/jwks.json", jwksURI)
	}
}

// TestSharedTokenFactory verifies that multiple engines sharing a
// TokenFactory all accept tokens from the shared JWKS.
func TestSharedTokenFactory(t *testing.T) {
	tf := atoltest.NewTokenFactory(t)

	engine1 := atoltest.NewEngine(t, atoltest.WithModel(testModel), atoltest.WithTokenFactory(tf))
	engine2 := atoltest.NewEngine(t, atoltest.WithModel(testModel), atoltest.WithTokenFactory(tf))

	token := tf.MintToken(atoltest.WithSubject("shared-user"))

	p1, _, _, _, err := engine1.Validator().ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("engine1: %v", err)
	}
	p2, _, _, _, err := engine2.Validator().ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("engine2: %v", err)
	}

	if p1.UserID != "shared-user" || p2.UserID != "shared-user" {
		t.Errorf("UserIDs = (%q, %q), want (shared-user, shared-user)", p1.UserID, p2.UserID)
	}
}
