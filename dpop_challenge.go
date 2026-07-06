package sdk

import (
	"net/http"
	"strings"
)

// challengeConfig accumulates ChallengeOption settings.
type challengeConfig struct {
	invalidProof bool
	useNonce     bool
	nonce        string
}

// ChallengeOption customizes the WWW-Authenticate DPoP challenge written by
// WriteDPoPChallenge.
type ChallengeOption func(*challengeConfig)

// WithInvalidProofError adds `error="invalid_dpop_proof"` to the challenge
// (RFC 9449 section 7.1). Use it when a DPoP proof was presented but failed
// validation, as opposed to a bare "DPoP is required" prompt.
func WithInvalidProofError() ChallengeOption {
	return func(c *challengeConfig) {
		c.invalidProof = true
	}
}

// WithDPoPNonce adds `error="use_dpop_nonce"` to the challenge and sets a
// `DPoP-Nonce` response header carrying nonce (RFC 9449 section 8). It is
// dormant until the issuer emits nonces; wiring it now lets the nonce flow be
// enabled without an API change. Passing WithDPoPNonce overrides
// WithInvalidProofError, since a nonce request is the more specific outcome.
func WithDPoPNonce(nonce string) ChallengeOption {
	return func(c *challengeConfig) {
		c.useNonce = true
		c.nonce = nonce
	}
}

// WriteDPoPChallenge writes an RFC 9449 section 7.1 resource-server DPoP
// challenge: a `WWW-Authenticate: DPoP ...` header and a 401 status. algs is
// the accepted proof-signing algorithm list; pass nil to advertise the SDK's
// supported set (DPoPSupportedAlgs).
//
// The challenge NEVER echoes a raw validator error string -- only the fixed,
// machine-readable RFC error codes and the public alg list. Keep any detail in
// server-side logs.
func WriteDPoPChallenge(w http.ResponseWriter, algs []string, opts ...ChallengeOption) {
	var cfg challengeConfig
	for _, o := range opts {
		o(&cfg)
	}

	if len(algs) == 0 {
		algs = make([]string, len(DPoPSupportedAlgs))
		for i, a := range DPoPSupportedAlgs {
			algs[i] = string(a)
		}
	}

	// RFC 9449 7.1: the error code lives inside the WWW-Authenticate params
	// for the RS 401 (unlike the AS token-endpoint 400 JSON body).
	params := []string{`algs="` + strings.Join(algs, " ") + `"`}
	switch {
	case cfg.useNonce:
		params = append(params, `error="use_dpop_nonce"`)
		if cfg.nonce != "" {
			w.Header().Set("DPoP-Nonce", cfg.nonce)
		}
	case cfg.invalidProof:
		params = append(params, `error="invalid_dpop_proof"`)
	}

	w.Header().Set("WWW-Authenticate", "DPoP "+strings.Join(params, ", "))
	w.WriteHeader(http.StatusUnauthorized)
}
