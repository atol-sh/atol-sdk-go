// Command atoltest-server runs a standalone mock OIDC server for E2E tests.
// It replaces external Node.js mock-auth servers with a single Go binary.
//
// Usage:
//
//	go run atol.sh/sdk-go/cmd/atoltest-server [-addr :3100]
//
// Endpoints:
//
//	GET  /.well-known/openid-configuration  — OIDC discovery document
//	GET  /.well-known/jwks.json             — JSON Web Key Set
//	POST /oauth/token                       — Mint a signed JWT
//	GET  /health                            — Health check
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
)

func main() {
	addr := flag.String("addr", ":3100", "listen address")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	pubDER, _ := json.Marshal(key.PublicKey)
	hash := sha256.Sum256(pubDER)
	kid := "atoltest-" + hex.EncodeToString(hash[:8])

	s := &server{key: key, kid: kid}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("GET /health", s.handleHealth)

	log.Printf("atoltest-server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	key *rsa.PrivateKey
	kid string
}

func (s *server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &s.key.PublicKey,
		KeyID:     s.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (s *server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	base := fmt.Sprintf("http://%s", r.Host)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"userinfo_endpoint":                     base + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	})
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	var req struct {
		Sub   string   `json:"sub"`
		Email string   `json:"email"`
		OrgID string   `json:"org_id"`
		Roles []string `json:"roles"`
		Plan  string   `json:"plan"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
	}

	if req.Sub == "" {
		req.Sub = "test-user"
	}
	if req.Email == "" {
		req.Email = "test@example.com"
	}

	issuer := fmt.Sprintf("http://%s", r.Host)
	token, err := s.mintToken(issuer, req.Sub, req.Email, req.OrgID, req.Roles, req.Plan)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400,
		"id_token":     token,
	})
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) mintToken(issuer, sub, email, orgID string, roles []string, plan string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: s.key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), s.kid),
	)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	now := time.Now()
	b := make([]byte, 16)
	rand.Read(b)

	standard := gojosejwt.Claims{
		Issuer:   issuer,
		Subject:  sub,
		IssuedAt: gojosejwt.NewNumericDate(now),
		Expiry:   gojosejwt.NewNumericDate(now.Add(24 * time.Hour)),
		ID:       hex.EncodeToString(b),
	}

	custom := map[string]any{
		"email": email,
	}
	if orgID != "" {
		custom["atol:org_id"] = orgID
	}
	if len(roles) > 0 {
		custom["atol:roles"] = roles
	}
	if plan != "" {
		custom["atol:plan"] = plan
	}

	return gojosejwt.Signed(signer).Claims(standard).Claims(custom).Serialize()
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
