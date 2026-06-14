// Package identity provides shared identity types used by both the control
// plane and the SDK for token validation and claims extraction.
package identity

// AtolClaims contains custom claims embedded in Atol-issued JWTs.
// These claims are included in both ID tokens and access tokens.
type AtolClaims struct {
	// OrgID is the tenant/organization the user belongs to.
	OrgID string `json:"atol:org_id,omitempty"`

	// Plan is the organization's subscription plan (free, pro, enterprise).
	Plan string `json:"atol:plan,omitempty"`

	// Roles assigned to the user within the organization.
	Roles []string `json:"atol:roles,omitempty"`

	// AuthMethod used for this session (password, passkey, social, magic_link).
	AuthMethod string `json:"atol:auth_method,omitempty"`

	// MFAVerified indicates whether multi-factor auth was completed.
	MFAVerified bool `json:"atol:mfa_verified,omitempty"`

	// EmailVerified indicates whether the user's email address is verified.
	// Standard OIDC claim (no atol: prefix).
	EmailVerified bool `json:"email_verified,omitempty"`

	// TrustDomain is the trust domain for SPIFFE-based identity federation.
	TrustDomain string `json:"atol:trust_domain,omitempty"`

	// AuthTime is the Unix timestamp of when authentication occurred.
	AuthTime int64 `json:"atol:auth_time,omitempty"`

	// IdentityID is the scheme-specific identity identifier (e.g., oidc://...).
	IdentityID string `json:"atol:identity_id,omitempty"`

	// IdentityScheme is the identity scheme (oidc, spiffe, saml).
	IdentityScheme string `json:"atol:identity_scheme,omitempty"`

	// WrappedDEK is the AES-256-GCM wrapped data encryption key (base64).
	// Present when the app requested deriveEncryptionKey during login.
	WrappedDEK string `json:"atol:wrapped_dek,omitempty"`

	// Cnf carries the RFC 7800 confirmation object. Populated on tokens
	// issued against a DPoP-bound session so resource servers can verify
	// the presented DPoP proof's JWK thumbprint against the binding.
	Cnf *ConfirmationClaim `json:"cnf,omitempty"`
}

// ConfirmationClaim is the RFC 7800 `cnf` object carried on sender-
// constrained access tokens. For DPoP (RFC 9449) this contains a single
// `jkt` entry whose value is the base64url-encoded SHA-256 thumbprint of
// the client's public JWK.
type ConfirmationClaim struct {
	// JKT is the RFC 7638 SHA-256 JWK thumbprint (base64url, no padding).
	// When non-empty, the corresponding access token is DPoP-bound.
	JKT string `json:"jkt,omitempty"`
}
