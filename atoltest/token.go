// Package atoltest provides testing utilities for applications built on
// the Atol SDK. It eliminates the need for external mock-auth servers,
// hand-rolled context helpers, and inline Zanzibar model YAML in tests.
package atoltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
)

// TokenFactory generates signed JWTs and serves their JWKS endpoint.
// Tokens produced by MintToken pass through the SDK's real TokenValidator.
// Safe for concurrent use.
type TokenFactory struct {
	privateKey *rsa.PrivateKey
	kid        string
	server     *httptest.Server
	issuer     string // the server URL, used as iss claim
}

// NewTokenFactory generates an RS256 key pair and starts a JWKS server.
// Cleanup is automatic via t.Cleanup.
func NewTokenFactory(t testing.TB) *TokenFactory {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("atoltest: generate RSA key: %v", err)
	}

	// Derive a deterministic kid from the public key.
	pubDER, err := json.Marshal(key.PublicKey)
	if err != nil {
		t.Fatalf("atoltest: marshal public key: %v", err)
	}
	hash := sha256.Sum256(pubDER)
	kid := "test-" + hex.EncodeToString(hash[:8])

	f := &TokenFactory{
		privateKey: key,
		kid:        kid,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", f.handleJWKS)
	srv := httptest.NewServer(mux)

	f.server = srv
	f.issuer = srv.URL

	t.Cleanup(f.Close)
	return f
}

// Close shuts down the internal JWKS server.
func (f *TokenFactory) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

// JWKSUrl returns the JWKS endpoint URL for SDK configuration.
func (f *TokenFactory) JWKSUrl() string {
	return f.server.URL + "/.well-known/jwks.json"
}

// Issuer returns the token issuer URL (the test server's address).
func (f *TokenFactory) Issuer() string {
	return f.issuer
}

// MintToken creates a signed JWT string. The token validates against this
// factory's JWKS endpoint using the SDK's real TokenValidator.
func (f *TokenFactory) MintToken(opts ...TokenOption) string {
	cfg := tokenConfig{
		subject:    "test-user",
		email:      "test@example.com",
		authMethod: "password",
		expiry:     1 * time.Hour,
	}
	for _, o := range opts {
		o(&cfg)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.privateKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), f.kid),
	)
	if err != nil {
		panic("atoltest: create signer: " + err.Error())
	}

	now := time.Now()
	jti := cfg.jti
	if jti == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			panic("atoltest: generate jti: " + err.Error())
		}
		jti = hex.EncodeToString(b)
	}

	standard := gojosejwt.Claims{
		Issuer:   f.issuer,
		Subject:  cfg.subject,
		IssuedAt: gojosejwt.NewNumericDate(now),
		Expiry:   gojosejwt.NewNumericDate(now.Add(cfg.expiry)),
		ID:       jti,
	}
	if cfg.audience != "" {
		standard.Audience = gojosejwt.Audience{cfg.audience}
	}

	custom := atolClaims{
		OrgID:          cfg.orgID,
		Plan:           cfg.plan,
		Roles:          cfg.roles,
		AuthMethod:     cfg.authMethod,
		MFAVerified:    cfg.mfaVerified,
		TrustDomain:    cfg.trustDomain,
		IdentityID:     cfg.identityID,
		IdentityScheme: cfg.identityScheme,
		Email:          cfg.email,
		EmailVerified:  cfg.emailVerified,
	}
	if cfg.authTime != nil {
		custom.AuthTime = cfg.authTime.Unix()
	}

	tok, err := gojosejwt.Signed(signer).Claims(standard).Claims(custom).Serialize()
	if err != nil {
		panic("atoltest: sign token: " + err.Error())
	}
	return tok
}

func (f *TokenFactory) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &f.privateKey.PublicKey,
		KeyID:     f.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keySet)
}

// TokenOption configures a test token.
type TokenOption func(*tokenConfig)

type tokenConfig struct {
	subject        string
	email          string
	orgID          string
	roles          []string
	plan           string
	authMethod     string
	mfaVerified    bool
	emailVerified  bool
	identityID     string
	identityScheme string
	trustDomain    string
	audience       string
	expiry         time.Duration
	jti            string
	authTime       *time.Time
}

// atolClaims mirrors identity.AtolClaims for JWT generation.
// We duplicate the struct to avoid an import cycle.
type atolClaims struct {
	OrgID          string   `json:"atol:org_id,omitempty"`
	Plan           string   `json:"atol:plan,omitempty"`
	Roles          []string `json:"atol:roles,omitempty"`
	AuthMethod     string   `json:"atol:auth_method,omitempty"`
	MFAVerified    bool     `json:"atol:mfa_verified,omitempty"`
	TrustDomain    string   `json:"atol:trust_domain,omitempty"`
	AuthTime       int64    `json:"atol:auth_time,omitempty"`
	IdentityID     string   `json:"atol:identity_id,omitempty"`
	IdentityScheme string   `json:"atol:identity_scheme,omitempty"`
	Email          string   `json:"email,omitempty"`
	EmailVerified  bool     `json:"email_verified,omitempty"`
}

// WithSubject sets the JWT subject (maps to Principal.UserID).
func WithSubject(sub string) TokenOption {
	return func(c *tokenConfig) { c.subject = sub }
}

// WithEmail sets the email claim.
func WithEmail(email string) TokenOption {
	return func(c *tokenConfig) { c.email = email }
}

// WithOrgID sets the atol:org_id custom claim.
func WithOrgID(orgID string) TokenOption {
	return func(c *tokenConfig) { c.orgID = orgID }
}

// WithRoles sets the atol:roles custom claim.
func WithRoles(roles ...string) TokenOption {
	return func(c *tokenConfig) { c.roles = roles }
}

// WithPlan sets the atol:plan custom claim.
func WithPlan(plan string) TokenOption {
	return func(c *tokenConfig) { c.plan = plan }
}

// WithAuthMethod sets the atol:auth_method custom claim.
func WithAuthMethod(method string) TokenOption {
	return func(c *tokenConfig) { c.authMethod = method }
}

// WithMFA sets atol:mfa_verified to true.
func WithMFA() TokenOption {
	return func(c *tokenConfig) { c.mfaVerified = true }
}

// WithEmailVerified sets the email_verified claim.
func WithEmailVerified(verified bool) TokenOption {
	return func(c *tokenConfig) { c.emailVerified = verified }
}

// WithIdentity sets the atol:identity_id and atol:identity_scheme claims.
func WithIdentity(id, scheme string) TokenOption {
	return func(c *tokenConfig) {
		c.identityID = id
		c.identityScheme = scheme
	}
}

// WithTrustDomain sets the atol:trust_domain claim.
func WithTrustDomain(domain string) TokenOption {
	return func(c *tokenConfig) { c.trustDomain = domain }
}

// WithAudience sets the JWT audience claim.
func WithAudience(aud string) TokenOption {
	return func(c *tokenConfig) { c.audience = aud }
}

// WithExpiry sets the token TTL. Default is 1 hour.
func WithExpiry(d time.Duration) TokenOption {
	return func(c *tokenConfig) { c.expiry = d }
}

// WithJTI sets the JWT ID (for session revocation testing).
func WithJTI(jti string) TokenOption {
	return func(c *tokenConfig) { c.jti = jti }
}

// WithAuthTime sets the atol:auth_time claim.
func WithAuthTime(t time.Time) TokenOption {
	return func(c *tokenConfig) { c.authTime = &t }
}
