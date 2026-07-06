package sdk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
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
	// ErrDPoPATHMismatch is returned when the proof carries an `ath`
	// (access-token hash, RFC 9449 section 4.2) that does not equal
	// base64url(SHA-256(accessToken)), or when a proof is required to carry
	// `ath` (WithRequireATH) but omits it.
	ErrDPoPATHMismatch = errors.New("dpop: ath claim does not match access token")
	// ErrDPoPReplayBackend is returned when the pluggable ReplayGuard fails
	// (e.g. a shared Redis/Firestore backend is unreachable). Per deny-by-
	// default, callers MUST treat this as a rejection: a replay check that
	// cannot run must never be assumed to have passed.
	ErrDPoPReplayBackend = errors.New("dpop: replay guard backend error")
)

// DPoP freshness defaults. These bound the acceptable age of a proof's `iat`
// claim and MUST be kept in parity with the Atol issuer's DPoP validator: a
// proof fresh enough for the token endpoint must also be fresh enough for a
// resource server, and vice versa. If the issuer's window drifts from these,
// legitimate proofs can be accepted at one hop and rejected at the other.
const (
	// DefaultDPoPSkew is the clock-skew tolerance applied to the `iat` claim.
	DefaultDPoPSkew = 30 * time.Second
	// DefaultDPoPMaxAge is how old a proof's `iat` may be before it is
	// rejected as stale. The effective replay window is DefaultDPoPMaxAge +
	// DefaultDPoPSkew.
	DefaultDPoPMaxAge = 60 * time.Second
)

// DPoPSupportedAlgs is the set of JWS algorithms accepted for DPoP proof
// signatures (RFC 9449). It is the single source of truth shared by the proof
// parser (validateString) and the WWW-Authenticate challenge builder
// (WriteDPoPChallenge) so the advertised set can never drift from the accepted
// set. It is also what the issuer advertises in
// `dpop_signing_alg_values_supported`.
var DPoPSupportedAlgs = []jose.SignatureAlgorithm{
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.RS256,
}

// ReplayGuard records DPoP proof `jti` values and reports whether each is
// fresh (never seen within its validity window). Implementations must be
// atomic check-and-record: a shared backend has to use an atomic primitive
// (e.g. SETNX / SET NX PX) or the cross-instance replay race simply moves
// into the store.
//
// CheckAndRecord returns fresh=true when jti was not previously recorded (and
// records it), fresh=false when jti is a replay. A non-nil error means the
// check could not be performed; per deny-by-default the validator rejects the
// proof (ErrDPoPReplayBackend) rather than assuming freshness. expiresAt is
// when the record may be evicted (the end of the proof's freshness window).
type ReplayGuard interface {
	CheckAndRecord(ctx context.Context, jti string, expiresAt time.Time) (fresh bool, err error)
}

// DPoPValidator verifies incoming DPoP proofs on resource-server requests.
// Stateful for replay protection; safe for concurrent use.
type DPoPValidator struct {
	// skew is the clock-skew tolerance applied to the `iat` claim.
	skew time.Duration
	// maxAge is how old a proof's iat can be before it's rejected as
	// stale. Any valid replay within this window is still caught by the
	// replay guard; stale-rejection just prunes the working set.
	maxAge time.Duration

	// requireATH makes a present-but-mismatched `ath` always fatal, and in
	// addition rejects a proof that omits `ath` entirely when an access token
	// is being bound. Default false: tolerate a missing ath (for rollout
	// while first/third-party clients catch up) but always reject a mismatch.
	requireATH bool

	// guard records seen jti values for replay protection. Defaults to an
	// in-memory per-process guard; swap via WithReplayGuard for a shared
	// backend in a horizontally-scaled deployment.
	guard ReplayGuard

	// metrics records bounded-cardinality DPoP outcome counters. May be nil.
	metrics *dpopMetrics
}

// DPoPValidatorOption configures a DPoPValidator.
type DPoPValidatorOption func(*DPoPValidator)

// WithReplayGuard installs a custom replay guard (e.g. a shared Redis-backed
// store) in place of the default in-memory guard. Use this when the resource
// server runs more than one instance: the in-memory default only detects
// replays within a single process, leaving a cross-instance replay window of
// roughly DefaultDPoPMaxAge + DefaultDPoPSkew.
func WithReplayGuard(g ReplayGuard) DPoPValidatorOption {
	return func(v *DPoPValidator) {
		if g != nil {
			v.guard = g
		}
	}
}

// WithRequireATH makes the validator reject a proof that omits the `ath`
// claim when an access token is being bound (RFC 9449 section 7.1 requires
// `ath` on protected-resource proofs). With the default (option unset) a
// missing `ath` is tolerated but a present-but-mismatched `ath` is always
// rejected.
func WithRequireATH() DPoPValidatorOption {
	return func(v *DPoPValidator) {
		v.requireATH = true
	}
}

// NewDPoPValidator returns a validator with RFC 9449-recommended defaults
// (DefaultDPoPSkew, DefaultDPoPMaxAge).
//
// The default replay guard is in-memory and per-process: it detects replays
// only within a single instance. A resource server running more than one
// instance (e.g. behind an autoscaler) has a cross-instance replay window of
// roughly DefaultDPoPMaxAge + DefaultDPoPSkew; install a shared backend via
// WithReplayGuard to close it.
func NewDPoPValidator(opts ...DPoPValidatorOption) *DPoPValidator {
	v := &DPoPValidator{
		skew:   DefaultDPoPSkew,
		maxAge: DefaultDPoPMaxAge,
		guard:  newMemoryReplayGuard(),
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// DPoPProof captures the validated content of an incoming proof JWT.
// The JKT field is the RFC 7638 thumbprint that resource servers compare
// against the access token's `cnf.jkt`.
type DPoPProof struct {
	JKT      string
	JTI      string
	HTM      string
	HTU      string
	ATH      string // access-token hash (RFC 9449 4.2); empty when the proof omits it.
	IssuedAt time.Time
}

// Validate reads the `DPoP` header off r, validates the proof against
// the expected method and request URI, and enforces that the proof's
// public-key thumbprint equals expectedJKT (the cnf.jkt from the access
// token). Callers should pass the empty string for expectedJKT only when
// they intentionally want to skip the binding check (not recommended).
//
// accessToken is the raw bearer/DPoP access token presented on the request.
// When non-empty the validator confirms the proof's `ath` claim equals
// base64url(SHA-256(accessToken)); pass "" only at the token endpoint (where
// no access token exists yet) to skip the `ath` check. See WithRequireATH for
// strict enforcement of a missing `ath`.
func (v *DPoPValidator) Validate(r *http.Request, expectedJKT, accessToken string) (*DPoPProof, error) {
	raw := r.Header.Get("DPoP")
	if raw == "" {
		return nil, ErrDPoPMissing
	}
	// Canonical URI the client should have signed over: scheme + host + path.
	// Strip the port when it matches the scheme's default so clients and
	// load balancers can disagree harmlessly.
	htu := reconstructRequestURI(r)
	proof, err := v.validateString(r.Context(), raw, r.Method, htu, expectedJKT, accessToken)
	v.metrics.recordOutcome(err)
	return proof, err
}

// validateString exists so tests can drive the validator without an
// http.Request. ctx is threaded to the replay guard so a shared backend can
// honor cancellation and deadlines.
func (v *DPoPValidator) validateString(ctx context.Context, raw, expectedHTM, expectedHTU, expectedJKT, expectedAccessToken string) (*DPoPProof, error) {
	tok, err := josejwt.ParseSigned(raw, DPoPSupportedAlgs)
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
		ATH string `json:"ath"`
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
	// ath (access-token hash) binds the proof to a specific access token so a
	// leaked proof cannot be presented alongside a different token that shares
	// the same key (RFC 9449 section 4.2). We only check when the caller
	// supplied the access token (i.e. at a protected resource, not the token
	// endpoint). A present-but-mismatched ath is ALWAYS fatal; a missing ath
	// is fatal only under WithRequireATH.
	if expectedAccessToken != "" {
		expectedATH := accessTokenHash(expectedAccessToken)
		switch {
		case claims.ATH == "" && v.requireATH:
			return nil, fmt.Errorf("%w: proof omits ath", ErrDPoPATHMismatch)
		case claims.ATH != "" && claims.ATH != expectedATH:
			return nil, fmt.Errorf("%w: proof ath does not match access token", ErrDPoPATHMismatch)
		}
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
	// Replay guard entries can be evicted once the proof can no longer be
	// accepted as fresh: iat + maxAge + skew.
	expiresAt := iat.Add(v.maxAge + v.skew)
	fresh, err := v.guard.CheckAndRecord(ctx, claims.JTI, expiresAt)
	if err != nil {
		// Fail closed: a replay check that could not run must not be assumed
		// to have passed.
		return nil, fmt.Errorf("%w: %v", ErrDPoPReplayBackend, err)
	}
	if !fresh {
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
		ATH:      claims.ATH,
		IssuedAt: iat,
	}, nil
}

// accessTokenHash returns base64url(SHA-256(token)) with no padding, matching
// the `ath` claim the client mints (RFC 9449 section 4.2).
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// memoryReplayGuard is the default in-memory ReplayGuard. Its behavior is
// identical to the original mu+seen map: it prunes expired entries on each
// call and rejects a jti it has already recorded. Per-process only.
type memoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newMemoryReplayGuard() *memoryReplayGuard {
	return &memoryReplayGuard{seen: make(map[string]time.Time)}
}

// CheckAndRecord implements ReplayGuard. It never returns an error (the
// in-memory guard cannot fail); the signature carries error only so shared
// backends can report I/O failures.
func (g *memoryReplayGuard) CheckAndRecord(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, t := range g.seen {
		if t.Before(now) {
			delete(g.seen, k)
		}
	}
	if _, replayed := g.seen[jti]; replayed {
		return false, nil
	}
	g.seen[jti] = expiresAt
	return true, nil
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
