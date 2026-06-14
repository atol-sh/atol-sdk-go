package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"atol.sh/sdk-go"
)

// TestExtractAuthToken_Schemes verifies the Authorization-header parser
// accepts Bearer and DPoP schemes (case-insensitive) and rejects others.
func TestExtractAuthToken_Schemes(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantScheme string
		wantToken  string
	}{
		{name: "empty", header: "", wantScheme: "", wantToken: ""},
		{name: "basic rejected", header: "Basic dXNlcjpwYXNz", wantScheme: "", wantToken: ""},
		{name: "bearer ok", header: "Bearer abc", wantScheme: "Bearer", wantToken: "abc"},
		{name: "dpop ok", header: "DPoP eyJ...", wantScheme: "DPoP", wantToken: "eyJ..."},
		{name: "dpop lower", header: "dpop eyJ...", wantScheme: "DPoP", wantToken: "eyJ..."},
		{name: "no space", header: "DPoP", wantScheme: "", wantToken: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			scheme, token := extractAuthToken(r)
			if scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", scheme, tt.wantScheme)
			}
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

// TestHTTPMiddleware_DPoPScheme_NoValidator confirms the nil-validator
// path fails closed for DPoP-scheme requests too: no validator means no
// authentication, so the request is rejected with 401 rather than a
// fabricated principal being passed through.
func TestHTTPMiddleware_DPoPScheme_NoValidator(t *testing.T) {
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	defer engine.Close()

	handler := HTTPMiddleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called without a validator")
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("Authorization", "DPoP opaque-token")
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestHTTPMiddleware_RequireDPoP rejects Bearer when the engine is
// configured with RequireDPoP=true, even if the token would otherwise
// validate.
func TestHTTPMiddleware_RequireDPoP(t *testing.T) {
	engine, err := sdk.New(sdk.Config{RequireDPoP: true})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	defer engine.Close()

	handler := HTTPMiddleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not run when DPoP is required and missing")
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("Authorization", "Bearer abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestIsDPoPVerified confirms the flag round-trips through context.
func TestIsDPoPVerified(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if sdk.IsDPoPVerified(r.Context()) {
		t.Fatal("fresh context should not be DPoP-verified")
	}
	ctx := sdk.ContextMarkDPoPVerified(r.Context())
	if !sdk.IsDPoPVerified(ctx) {
		t.Error("ContextMarkDPoPVerified did not stick")
	}
}
