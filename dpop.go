package sdk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.SHA256
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// DPoP (RFC 9449) resource-server validator.
//
// This is the consumer-side counterpart to the DPoP validator on the
// Atol issuer. It is invoked from SDK middleware when a request arrives
// with a DPoP-scheme Authorization header: the middleware hands us the
// incoming request plus the `cnf.jkt` value parsed from the access
// token, and we confirm that the attached `DPoP` proof was minted by
// the same keypair whose thumbprint is bound to the token.
//
// Goals:
//   - Validate the proof JWT itself (typ, alg, jwk, htm, htu, iat, jti).
//   - Enforce sender-constraint by requiring `thumbprint(proof.jwk) == token.cnf.jkt`.
//   - Reject replay via a short-lived jti cache keyed per-process.
//
// What we do NOT do:
//   - Fetch keys from JWKS. DPoP proofs are self-contained -- the public
//     key travels in the proof header.
//   - Nonce flow (RFC 9449 section 8). Nonces are server-initiated; the issuer
//     doesn't emit them yet, so neither does the SDK.

// DPoP errors mirror the issuer-side taxonomy so callers that bridge
// both can share error handling.
var (
	ErrDPoPMissing        = errors.New("dpop: missing DPoP header")
	ErrDPoPMalformed      = errors.New("dpop: malformed proof JWT")
	ErrDPoPSignature      = errors.New("dpop: signature verification failed")
	ErrDPoPMethodMismatch = errors.New("dpop: htm claim does not match HTTP method")
	ErrDPoPURIMismatch    = errors.New("dpop: htu claim does not match request URI")
	ErrDPoPStale          = errors.New("dpop: iat outside acceptable window")
	ErrDPoPReplay         = errors.New("dpop: jti has been seen recently (replay)")
	ErrDPoPJKTMismatch    = errors.New("dpop: proof key does not match access token cnf.jkt")
)

// DPoPValidator verifies incoming DPoP proofs on resource-server requests.
// Stateful for replay protection; safe for concurrent use.
type DPoPValidator struct {
	// skew is the clock-skew tolerance applied to the `iat` claim.
	skew time.Duration
	// maxAge is how old a proof's iat can be before it's rejected as
	// stale. Any valid replay within this window is still caught by the
	// jti cache; stale-rejection just prunes the working set.
	maxAge time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewDPoPValidator returns a validator with RFC 9449-recommended defaults
// (30s skew, 60s max age).
func NewDPoPValidator() *DPoPValidator {
	return &DPoPValidator{
		skew:   30 * time.Second,
		maxAge: 60 * time.Second,
		seen:   make(map[string]time.Time),
	}
}

// DPoPProof captures the validated content of an incoming proof JWT.
// The JKT field is the RFC 7638 thumbprint that resource servers compare
// against the access token's `cnf.jkt`.
type DPoPProof struct {
	JKT      string
	JTI      string
	HTM      string
	HTU      string
	IssuedAt time.Time
}

// Validate reads the `DPoP` header off r, validates the proof against
// the expected method and request URI, and enforces that the proof's
// public-key thumbprint equals expectedJKT (the cnf.jkt from the access
// token). Callers should pass the empty string for expectedJKT only when
// they intentionally want to skip the binding check (not recommended).
func (v *DPoPValidator) Validate(r *http.Request, expectedJKT string) (*DPoPProof, error) {
	raw := r.Header.Get("DPoP")
	if raw == "" {
		return nil, ErrDPoPMissing
	}
	// Canonical URI the client should have signed over: scheme + host + path.
	// Strip the port when it matches the scheme's default so clients and
	// load balancers can disagree harmlessly.
	htu := reconstructRequestURI(r)
	return v.validateString(raw, r.Method, htu, expectedJKT)
}

// validateString exists so tests can drive the validator without an
// http.Request.
func (v *DPoPValidator) validateString(raw, expectedHTM, expectedHTU, expectedJKT string) (*DPoPProof, error) {
	tok, err := josejwt.ParseSigned(
		raw,
		[]jose.SignatureAlgorithm{
			jose.ES256,
			jose.ES384,
			jose.ES512,
			jose.PS256,
			jose.RS256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoPMalformed, err)
	}
	if len(tok.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature header", ErrDPoPMalformed)
	}
	hdr := tok.Headers[0]

	// RFC 9449 section 4.2: typ MUST be "dpop+jwt".
	if hdr.ExtraHeaders == nil || hdr.ExtraHeaders["typ"] != "dpop+jwt" {
		return nil, fmt.Errorf("%w: typ header must be dpop+jwt", ErrDPoPMalformed)
	}
	if hdr.JSONWebKey == nil {
		return nil, fmt.Errorf("%w: missing jwk header", ErrDPoPMalformed)
	}
	key := *hdr.JSONWebKey
	if !key.IsPublic() {
		return nil, fmt.Errorf("%w: jwk is not a public key", ErrDPoPMalformed)
	}
	switch key.Key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		// OK.
	default:
		return nil, fmt.Errorf("%w: unsupported jwk key type %T", ErrDPoPMalformed, key.Key)
	}

	var claims struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
	}
	if err := tok.Claims(key.Key, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoPSignature, err)
	}

	if !strings.EqualFold(claims.HTM, expectedHTM) {
		return nil, fmt.Errorf("%w: proof.htm=%q, request method=%q",
			ErrDPoPMethodMismatch, claims.HTM, expectedHTM)
	}
	if normalizeDPoPURI(claims.HTU) != normalizeDPoPURI(expectedHTU) {
		return nil, fmt.Errorf("%w: proof.htu=%q, request URI=%q",
			ErrDPoPURIMismatch, claims.HTU, expectedHTU)
	}
	if claims.IAT == 0 {
		return nil, fmt.Errorf("%w: iat missing", ErrDPoPMalformed)
	}
	iat := time.Unix(claims.IAT, 0)
	now := time.Now()
	if iat.After(now.Add(v.skew)) || iat.Before(now.Add(-v.maxAge-v.skew)) {
		return nil, fmt.Errorf("%w: iat=%s now=%s maxAge=%s",
			ErrDPoPStale, iat.Format(time.RFC3339), now.Format(time.RFC3339), v.maxAge)
	}
	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: jti missing", ErrDPoPMalformed)
	}
	if !v.recordJTI(claims.JTI, iat) {
		return nil, ErrDPoPReplay
	}

	jkt, err := jwkThumbprintSHA256(&key)
	if err != nil {
		return nil, fmt.Errorf("%w: thumbprint: %v", ErrDPoPMalformed, err)
	}
	if expectedJKT != "" && jkt != expectedJKT {
		return nil, fmt.Errorf("%w: token jkt=%q, proof jkt=%q",
			ErrDPoPJKTMismatch, expectedJKT, jkt)
	}

	return &DPoPProof{
		JKT:      jkt,
		JTI:      claims.JTI,
		HTM:      claims.HTM,
		HTU:      claims.HTU,
		IssuedAt: iat,
	}, nil
}

func (v *DPoPValidator) recordJTI(jti string, iat time.Time) bool {
	cutoff := time.Now().Add(-v.maxAge - v.skew)
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, t := range v.seen {
		if t.Before(cutoff) {
			delete(v.seen, k)
		}
	}
	if _, replayed := v.seen[jti]; replayed {
		return false
	}
	v.seen[jti] = iat
	return true
}

// reconstructRequestURI returns scheme://host/path for the request, using
// the `X-Forwarded-Proto` header when TLS is terminated upstream. Query
// and fragment are deliberately omitted per RFC 9449 section 4.2.
func reconstructRequestURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		// Trust the first entry only; anything more is header injection.
		if idx := strings.Index(xf, ","); idx >= 0 {
			xf = xf[:idx]
		}
		scheme = strings.ToLower(strings.TrimSpace(xf))
	}
	u := &url.URL{Scheme: scheme, Host: r.Host, Path: r.URL.Path}
	return u.String()
}

// normalizeDPoPURI canonicalizes an htu value: drops query + fragment,
// elides default ports, and normalizes an empty path to "/".
func normalizeDPoPURI(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	u.RawQuery = ""
	u.Fragment = ""
	host := u.Host
	if strings.HasSuffix(host, ":80") && u.Scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	if strings.HasSuffix(host, ":443") && u.Scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	}
	u.Host = host
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// jwkThumbprintSHA256 returns the RFC 7638 SHA-256 thumbprint in base64url
// (no padding), matching what the issuer writes into cnf.jkt.
func jwkThumbprintSHA256(key *jose.JSONWebKey) (string, error) {
	raw, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
