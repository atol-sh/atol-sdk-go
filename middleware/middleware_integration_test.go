package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
	"atol.sh/sdk-go/middleware"
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

// TestHTTPMiddleware_ValidToken verifies the full HTTP middleware pipeline
// with a real JWT: token extraction → JWKS validation → principal injection.
func TestHTTPMiddleware_ValidToken(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	token := engine.Tokens().MintToken(
		atoltest.WithSubject("remi"),
		atoltest.WithEmail("user@example.com"),
		atoltest.WithOrgID("acme"),
		atoltest.WithRoles("admin"),
	)

	var captured *sdk.Principal
	handler := middleware.HTTPMiddleware(engine.Atol)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := sdk.UserFromContext(r.Context())
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			captured = p
			w.WriteHeader(http.StatusOK)
		}),
	)

	r := httptest.NewRequest("GET", "/api/resource", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = "192.168.1.100:9090"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if captured == nil {
		t.Fatal("principal not captured")
	}
	if captured.UserID != "remi" {
		t.Errorf("UserID = %q, want %q", captured.UserID, "remi")
	}
	if captured.OrgID != "acme" {
		t.Errorf("OrgID = %q, want %q", captured.OrgID, "acme")
	}
	if captured.ClientIP != "192.168.1.100" {
		t.Errorf("ClientIP = %q, want %q", captured.ClientIP, "192.168.1.100")
	}
}

// TestHTTPMiddleware_InvalidToken verifies that an invalid JWT is rejected
// with 401 when a real token validator is configured.
func TestHTTPMiddleware_InvalidToken(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	handler := middleware.HTTPMiddleware(engine.Atol)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Error("handler should not be called for invalid token")
			w.WriteHeader(http.StatusOK)
		}),
	)

	r := httptest.NewRequest("GET", "/api/resource", nil)
	r.Header.Set("Authorization", "Bearer invalid.jwt.token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestHTTPMiddleware_ValidToken_ClaimsInContext verifies that JWT claims
// and identity are set in context after successful validation.
func TestHTTPMiddleware_ValidToken_ClaimsInContext(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))

	token := engine.Tokens().MintToken(
		atoltest.WithSubject("alice"),
		atoltest.WithIdentity("oidc://auth.atol.sh/abc", "oidc"),
	)

	var hasIdentity bool
	var hasClaims bool
	handler := middleware.HTTPMiddleware(engine.Atol)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hasIdentity = sdk.IdentityFromContext(r.Context())
			_, hasClaims = sdk.ClaimsFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !hasIdentity {
		t.Error("identity not set in context")
	}
	if !hasClaims {
		t.Error("claims not set in context")
	}
}

// TestHTTPMiddleware_XForwardedFor verifies that ClientIP is correctly
// extracted from the X-Forwarded-For header through real JWT validation.
func TestHTTPMiddleware_XForwardedFor(t *testing.T) {
	engine := atoltest.NewEngine(t, atoltest.WithModel(testModel))
	token := engine.Tokens().MintToken(atoltest.WithSubject("alice"))

	var clientIP string
	handler := middleware.HTTPMiddleware(engine.Atol)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := sdk.UserFromContext(r.Context())
			clientIP = p.ClientIP
			w.WriteHeader(http.StatusOK)
		}),
	)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	r.RemoteAddr = "10.0.0.1:8080"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if clientIP != "203.0.113.50" {
		t.Errorf("ClientIP = %q, want %q", clientIP, "203.0.113.50")
	}
}
