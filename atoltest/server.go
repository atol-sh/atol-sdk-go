package atoltest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockOIDCServer is an in-process mock OIDC provider for E2E tests. It serves
// JWKS, OpenID discovery, and a token endpoint. Tokens produced by this server
// pass the SDK's real TokenValidator.
type MockOIDCServer struct {
	factory *TokenFactory
	server  *httptest.Server
}

// NewMockOIDCServer creates a mock OIDC server. Cleanup is automatic via t.Cleanup.
func NewMockOIDCServer(t testing.TB) *MockOIDCServer {
	t.Helper()

	f := NewTokenFactory(t)
	s := &MockOIDCServer{factory: f}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", f.handleJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("GET /health", s.handleHealth)

	srv := httptest.NewServer(mux)
	s.server = srv

	// Update the factory's issuer to match this server's URL.
	f.issuer = srv.URL
	// Close the factory's standalone JWKS server since this server handles JWKS.
	f.server.Close()
	f.server = srv

	t.Cleanup(s.Close)
	return s
}

// URL returns the server's base URL.
func (s *MockOIDCServer) URL() string {
	return s.server.URL
}

// Close shuts down the server.
func (s *MockOIDCServer) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// TokenFactory returns the factory for direct token minting (bypassing HTTP).
func (s *MockOIDCServer) TokenFactory() *TokenFactory {
	return s.factory
}

func (s *MockOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := s.server.URL
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"userinfo_endpoint":                     base + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (s *MockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "failed to read body",
		})
		return
	}

	var req tokenRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "invalid JSON body",
			})
			return
		}
	}

	// Build token options from the request body.
	var opts []TokenOption
	if req.Sub != "" {
		opts = append(opts, WithSubject(req.Sub))
	}
	if req.Email != "" {
		opts = append(opts, WithEmail(req.Email))
	}
	if req.OrgID != "" {
		opts = append(opts, WithOrgID(req.OrgID))
	}
	if len(req.Roles) > 0 {
		opts = append(opts, WithRoles(req.Roles...))
	}
	if req.Plan != "" {
		opts = append(opts, WithPlan(req.Plan))
	}

	token := s.factory.MintToken(opts...)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     token,
	})
}

func (s *MockOIDCServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type tokenRequest struct {
	Sub   string   `json:"sub"`
	Email string   `json:"email"`
	OrgID string   `json:"org_id"`
	Roles []string `json:"roles"`
	Plan  string   `json:"plan"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
