package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"atol.sh/sdk-go"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "empty authorization header",
			header: "",
			want:   "",
		},
		{
			name:   "basic auth ignored",
			header: "Basic xyz",
			want:   "",
		},
		{
			name:   "bearer without space",
			header: "Bearer",
			want:   "",
		},
		{
			name:   "valid bearer token",
			header: "Bearer abc123",
			want:   "abc123",
		},
		{
			name:   "bearer lowercase",
			header: "bearer abc123",
			want:   "abc123",
		},
		{
			name:   "bearer mixed case",
			header: "BEARER mytoken",
			want:   "mytoken",
		},
		{
			name:   "token with dots (JWT-like)",
			header: "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig",
			want:   "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			got := extractBearerToken(r)
			if got != tt.want {
				t.Errorf("extractBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xRealIP    string
		remoteAddr string
		want       string
	}{
		{
			name:       "X-Forwarded-For single IP",
			xff:        "192.168.1.1",
			remoteAddr: "10.0.0.1:8080",
			want:       "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For multiple IPs takes first",
			xff:        "  203.0.113.50 , 70.41.3.18, 150.172.238.178",
			remoteAddr: "10.0.0.1:8080",
			want:       "203.0.113.50",
		},
		{
			name:       "no XFF uses X-Real-IP",
			xRealIP:    "172.16.0.5",
			remoteAddr: "10.0.0.1:8080",
			want:       "172.16.0.5",
		},
		{
			name:       "X-Real-IP with whitespace trimmed",
			xRealIP:    "  172.16.0.5  ",
			remoteAddr: "10.0.0.1:8080",
			want:       "172.16.0.5",
		},
		{
			name:       "fallback to RemoteAddr strips port",
			remoteAddr: "10.0.0.1:8080",
			want:       "10.0.0.1",
		},
		{
			name:       "RemoteAddr without port returned as-is",
			remoteAddr: "10.0.0.1",
			want:       "10.0.0.1",
		},
		{
			name:       "XFF takes priority over X-Real-IP",
			xff:        "1.2.3.4",
			xRealIP:    "5.6.7.8",
			remoteAddr: "10.0.0.1:8080",
			want:       "1.2.3.4",
		},
		{
			name:       "IPv6 RemoteAddr with port",
			remoteAddr: "[::1]:8080",
			want:       "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			r.RemoteAddr = tt.remoteAddr
			got := extractClientIP(r)
			if got != tt.want {
				t.Errorf("extractClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHTTPMiddleware_NoToken(t *testing.T) {
	// When no Authorization header is set, the middleware returns 401
	// before ever accessing the engine, so nil is safe here.
	handler := HTTPMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	tests := []struct {
		name   string
		header string
	}{
		{name: "no authorization header", header: ""},
		{name: "invalid bearer format (no space)", header: "Bearer"},
		{name: "basic auth", header: "Basic dXNlcjpwYXNz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
		})
	}
}

// TestHTTPMiddleware_NilValidator_FailsClosed pins the deny-by-default
// behavior: with no token validator configured (no JWKSUrl), every request
// is rejected with 401 -- the middleware never fabricates a principal.
func TestHTTPMiddleware_NilValidator_FailsClosed(t *testing.T) {
	t.Parallel()

	// Create an Atol instance with no JWKS URL so the validator is nil.
	engine, err := sdk.New(sdk.Config{})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	defer engine.Close()

	// Verify the validator is indeed nil.
	if engine.Validator() != nil {
		t.Fatal("expected nil validator for empty config")
	}

	tests := []struct {
		name  string
		token string
	}{
		{name: "opaque bearer token", token: "some-opaque-token"},
		{name: "JWT-like token", token: "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := HTTPMiddleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("next handler must not be called without a validator")
			}))

			r := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
			r.Header.Set("Authorization", "Bearer "+tt.token)
			r.RemoteAddr = "192.168.1.100:9090"
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
		})
	}
}
