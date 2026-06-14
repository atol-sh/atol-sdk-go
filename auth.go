package sdk

import (
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"

	atolidentity "atol.sh/sdk-go/identity"
)

// tokenValidationLeeway is the clock-skew tolerance applied to JWT exp/nbf
// checks. 30s absorbs NTP jitter between client and server and the small
// gap between the SDK's proactive silent-renew (fires 60s before exp) and
// the moment the token hits the resource server.
const tokenValidationLeeway = 30 * time.Second

// TokenValidator validates Atol-issued JWTs and extracts claims.
type TokenValidator struct {
	jwks     *atolidentity.JWKSFetcher
	issuer   string
	audience string // optional: when set, JWT aud must contain this value
}

// NewTokenValidator creates a validator that checks JWTs against JWKS.
// audience is optional — pass "" to skip audience validation.
func NewTokenValidator(jwksURL, issuer, audience string) *TokenValidator {
	return &TokenValidator{
		jwks:     atolidentity.NewJWKSFetcher(jwksURL),
		issuer:   issuer,
		audience: audience,
	}
}

// ValidateToken parses and validates a JWT, returning the principal, identity, claims, and session ID (jti).
func (v *TokenValidator) ValidateToken(ctx context.Context, rawToken string) (*Principal, *Identity, *atolidentity.AtolClaims, string, error) {
	tok, err := gojosejwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("parse token: %w", err)
	}

	// Get the key ID from the token header.
	if len(tok.Headers) == 0 {
		return nil, nil, nil, "", fmt.Errorf("token has no headers")
	}
	kid := tok.Headers[0].KeyID

	// Look up the signing key.
	keys, err := v.jwks.FindKey(ctx, kid)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("find signing key: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil, nil, "", fmt.Errorf("unknown signing key: %s", kid)
	}

	// Verify signature and extract claims.
	var standard gojosejwt.Claims
	var custom atolidentity.AtolClaims
	if err := tok.Claims(keys[0].Key, &standard, &custom); err != nil {
		return nil, nil, nil, "", fmt.Errorf("verify claims: %w", err)
	}

	// Validate standard claims with a 30s clock-skew tolerance. Without
	// leeway a client whose clock is a second ahead of the server (or vice
	// versa) fails validation right at the exp boundary; 30s matches common
	// OIDC library defaults and absorbs both NTP jitter and small pauses
	// between the SDK's proactive renew (fires 60s before exp) and the
	// request actually hitting the resource server.
	expected := gojosejwt.Expected{
		Issuer: v.issuer,
		Time:   time.Now(),
	}
	if v.audience != "" {
		expected.AnyAudience = gojosejwt.Audience{v.audience}
	}
	if err := standard.ValidateWithLeeway(expected, tokenValidationLeeway); err != nil {
		return nil, nil, nil, "", fmt.Errorf("validate claims: %w", err)
	}

	// Populate principal with all available claims.
	var authTime time.Time
	if custom.AuthTime > 0 {
		authTime = time.Unix(custom.AuthTime, 0)
	}

	principal := &Principal{
		UserID:        standard.Subject,
		IdentityID:    custom.IdentityID,
		OrgID:         custom.OrgID,
		Email:         "", // Email is set from ID token claims if available.
		EmailVerified: custom.EmailVerified,
		AuthMethod:    custom.AuthMethod,
		Roles:         custom.Roles,
		Plan:          custom.Plan,
		MFAVerified:   custom.MFAVerified,
		TrustDomain:   custom.TrustDomain,
		AuthTime:      authTime,
	}

	// Build scheme-specific identity from claims.
	identity := &Identity{
		ID:         custom.IdentityID,
		Scheme:     custom.IdentityScheme,
		AuthMethod: custom.AuthMethod,
	}

	return principal, identity, &custom, standard.ID, nil
}
