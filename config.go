// Package sdk provides the embeddable Atol SDK for Go applications.
// It bundles token validation, OPA policy evaluation, and Zanzibar
// relationship checks into a single engine.
package sdk

import (
	"time"

	"atol.sh/sdk-go/device"
)

// Config holds SDK configuration.
type Config struct {
	// ControlPlaneURL is the Atol control plane base URL.
	ControlPlaneURL string

	// KeyID is the publishable key identifier (atol_kid_...).
	// Safe for frontend use. Required for all control plane calls.
	// Create one in the dashboard (app.atol.sh) under APIs > New API Key.
	KeyID string

	// SecretKey is the private secret (atol_sk_...).
	// Required for server-side SDK. Never transmitted — used to HMAC-sign requests.
	SecretKey string

	// StoreID is the organization/tenant identifier.
	StoreID string

	// ZanzibarModelPath is an optional path to a local YAML model file.
	// When set, the model is loaded from this file at New() time. If empty,
	// the model is fetched from the control plane via bootstrap.
	ZanzibarModelPath string

	// Issuer is the expected JWT issuer URL (iss claim). Defaults to ControlPlaneURL.
	// Set this when the control plane network address differs from the token issuer
	// (e.g., Docker: ControlPlaneURL=host.docker.internal:9080, Issuer=localhost:9080).
	Issuer string

	// Audience is the expected JWT audience (aud claim). Optional.
	// When set, tokens must contain this audience. Typically the API identifier
	// (e.g., "https://api.example.com").
	Audience string

	// JWKSUrl is the JWKS endpoint URL. Defaults to ControlPlaneURL + "/.well-known/jwks.json".
	JWKSUrl string

	// BootstrapTimeout is the max time for Bootstrap() to pull the initial
	// state (model, tuples, bundle, data) and run materializers. Default 10s.
	BootstrapTimeout time.Duration

	// DisableSync turns off live mutation sync after bootstrap.
	// The zero value (false) means sync is enabled.
	DisableSync bool

	// DecisionLogFlushInterval is how often decision logs are flushed. Default 5s.
	DecisionLogFlushInterval time.Duration

	// DecisionLogBufferSize is the max buffered decision log entries. Default 10000.
	DecisionLogBufferSize int

	// Device configures device intelligence context propagation.
	// When Device.Enabled is true, the SDK middleware extracts the device ID
	// from the X-Atol-Device-Id header and injects it into the authorization
	// context so Rego policies can reference input.device.*.
	Device device.Config

	// RequireDPoP rejects tokens that arrive without a DPoP proof. When false
	// (default), the middleware accepts both Bearer and DPoP schemes and only
	// enforces proof validation on the DPoP path. Setting this to true makes
	// sender-constrained tokens mandatory -- useful once all first-party
	// clients are on a DPoP-capable SDK. Corresponds to the issuer's
	// `dpopMode: required` setting.
	RequireDPoP bool

	// MaxStaleness is the opt-in budget for the staleness gate (ADR 0018).
	// When zero (default) the gate is off and reads keep their existing
	// fail-open-on-partition behavior. When set, a synced instance whose
	// stream has been disconnected longer than this budget is treated as
	// stale and handled per StalenessMode. Prefer WithMaxStaleness to set
	// both fields together.
	MaxStaleness time.Duration

	// StalenessMode selects how a stale read is handled. The zero value
	// (StalenessOff) disables the gate even if MaxStaleness is set.
	StalenessMode StalenessMode

	// BootstrapInterval forces a periodic full re-bootstrap to bound policy
	// age (ADR 0018). Zero (default) disables it. It runs on its own
	// lifecycle, independent of live sync, so it bounds policy age even when
	// DisableSync is set. Prefer WithBootstrapInterval.
	BootstrapInterval time.Duration
}

// defaults sets default values for zero-value fields.
func (c *Config) defaults() {
	if c.Issuer == "" {
		c.Issuer = c.ControlPlaneURL
	}
	if c.JWKSUrl == "" {
		// Derive JWKS URL from Issuer (per-tenant subdomain) when available,
		// falling back to ControlPlaneURL. With per-tenant issuers, the JWKS
		// lives at the issuer's domain (e.g., https://acme.atol.sh/.well-known/jwks.json).
		base := c.Issuer
		if base == "" {
			base = c.ControlPlaneURL
		}
		if base != "" {
			c.JWKSUrl = base + "/.well-known/jwks.json"
		}
	}
	if c.BootstrapTimeout == 0 {
		c.BootstrapTimeout = 10 * time.Second
	}
	if c.DecisionLogFlushInterval == 0 {
		c.DecisionLogFlushInterval = 5 * time.Second
	}
	if c.DecisionLogBufferSize == 0 {
		c.DecisionLogBufferSize = 10000
	}

	// Inherit control plane URL and API key for device intelligence if not set.
	if c.Device.ControlPlaneURL == "" {
		c.Device.ControlPlaneURL = c.ControlPlaneURL
	}
	if c.Device.APIKey == "" {
		c.Device.APIKey = c.KeyID
	}
	c.Device.Defaults()
}
