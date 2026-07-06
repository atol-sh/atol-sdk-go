package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// testProofBuilder mints DPoP proofs signed with a fresh ES256 keypair.
// Mirrors what the React SDK produces in the browser. Uses testing.TB so
// both *testing.T and *testing.F can seed fuzz tests with a valid proof.
type testProofBuilder struct {
	t      testing.TB
	signer jose.Signer
	pub    jose.JSONWebKey
}

func newTestProofBuilder(t testing.TB) *testProofBuilder {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.ES256)}
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt")
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: priv}},
		opts,
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return &testProofBuilder{t: t, signer: signer, pub: pub}
}

func (b *testProofBuilder) jkt(t *testing.T) string {
	t.Helper()
	jkt, err := jwkThumbprintSHA256(&b.pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return jkt
}

type proofOpts struct {
	htm string
	htu string
	iat time.Time
	jti string
	ath string // when set, stamped verbatim as the ath claim
}

func (b *testProofBuilder) sign(opts proofOpts) string {
	b.t.Helper()
	if opts.iat.IsZero() {
		opts.iat = time.Now()
	}
	if opts.jti == "" {
		opts.jti = fmt.Sprintf("jti-%d", time.Now().UnixNano())
	}
	claims := map[string]any{
		"jti": opts.jti,
		"htm": opts.htm,
		"htu": opts.htu,
		"iat": opts.iat.Unix(),
	}
	if opts.ath != "" {
		claims["ath"] = opts.ath
	}
	tok, err := josejwt.Signed(b.signer).Claims(claims).Serialize()
	if err != nil {
		b.t.Fatalf("sign: %v", err)
	}
	return tok
}

// athFor returns the expected ath value for an access token:
// base64url(SHA-256(token)) with no padding.
func athFor(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestDPoPValidator_HappyPath(t *testing.T) {
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://api.example.com/rpc"})

	got, err := v.validateString(context.Background(), proof, "POST", "http://api.example.com/rpc", b.jkt(t), "")
	if err != nil {
		t.Fatalf("validateString: %v", err)
	}
	if got.JKT != b.jkt(t) {
		t.Errorf("JKT = %q, want %q", got.JKT, b.jkt(t))
	}
	if got.HTM != "POST" {
		t.Errorf("HTM = %q, want POST", got.HTM)
	}
}

func TestDPoPValidator_RejectJKTMismatch(t *testing.T) {
	// A valid proof that uses the wrong key MUST be rejected against a
	// fixed expected jkt -- that's the sender-constraint guarantee.
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})

	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", "some-other-jkt", "")
	if !errors.Is(err, ErrDPoPJKTMismatch) {
		t.Errorf("expected ErrDPoPJKTMismatch, got %v", err)
	}
}

func TestDPoPValidator_AllowEmptyExpectedJKT(t *testing.T) {
	// Passing expectedJKT="" disables the binding check (useful for
	// the edge case where the access token has no cnf claim but the
	// client still wants to use DPoP scheme).
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	if _, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", "", ""); err != nil {
		t.Errorf("empty expected JKT should not fail: %v", err)
	}
}

func TestDPoPValidator_RejectBadSignature(t *testing.T) {
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	mangled := proof[:len(proof)-4] + "aaaa"
	_, err := v.validateString(context.Background(), mangled, "POST", "http://x/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPSignature) && !errors.Is(err, ErrDPoPMalformed) {
		t.Errorf("expected signature/malformed error, got %v", err)
	}
}

func TestDPoPValidator_RejectMethodMismatch(t *testing.T) {
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "GET", htu: "http://x/rpc"})
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPMethodMismatch) {
		t.Errorf("expected ErrDPoPMethodMismatch, got %v", err)
	}
}

func TestDPoPValidator_RejectURIMismatch(t *testing.T) {
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	_, err := v.validateString(context.Background(), proof, "POST", "http://evil.com/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPURIMismatch) {
		t.Errorf("expected ErrDPoPURIMismatch, got %v", err)
	}
}

func TestDPoPValidator_RejectStaleIAT(t *testing.T) {
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{
		htm: "POST",
		htu: "http://x/rpc",
		iat: time.Now().Add(-5 * time.Minute),
	})
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPStale) {
		t.Errorf("expected ErrDPoPStale, got %v", err)
	}
}

func TestDPoPValidator_RejectReplay(t *testing.T) {
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{
		htm: "POST",
		htu: "http://x/rpc",
		jti: "replay-jti",
	})
	if _, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), ""); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPReplay) {
		t.Errorf("expected ErrDPoPReplay, got %v", err)
	}
}

func TestDPoPValidator_ATHMatch(t *testing.T) {
	// A proof carrying the correct ath for the presented token is accepted.
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	const token = "access-token-abc"
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc", ath: athFor(token)})
	if _, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), token); err != nil {
		t.Errorf("matching ath should validate, got %v", err)
	}
}

func TestDPoPValidator_ATHMismatch(t *testing.T) {
	// A proof bound (via ath) to a DIFFERENT token is always rejected, even
	// though the key and everything else are valid.
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc", ath: athFor("some-other-token")})
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "the-real-token")
	if !errors.Is(err, ErrDPoPATHMismatch) {
		t.Errorf("expected ErrDPoPATHMismatch, got %v", err)
	}
}

func TestDPoPValidator_ATHMissingTolerated(t *testing.T) {
	// Default policy: a proof that omits ath is tolerated even when a token
	// is presented (rollout-friendly). The mismatch case above still fires.
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	if _, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "any-token"); err != nil {
		t.Errorf("missing ath should be tolerated by default, got %v", err)
	}
}

func TestDPoPValidator_ATHMissingRejectedWhenRequired(t *testing.T) {
	// With WithRequireATH a proof that omits ath is rejected when a token is
	// presented (RFC 9449 7.1 strict mode).
	v := NewDPoPValidator(WithRequireATH())
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "any-token")
	if !errors.Is(err, ErrDPoPATHMismatch) {
		t.Errorf("expected ErrDPoPATHMismatch when ath required but missing, got %v", err)
	}
}

func TestDPoPValidator_ATHSkippedAtTokenEndpoint(t *testing.T) {
	// accessToken=="" (token endpoint) skips the ath check entirely, even
	// under WithRequireATH.
	v := NewDPoPValidator(WithRequireATH())
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/token"})
	if _, err := v.validateString(context.Background(), proof, "POST", "http://x/token", b.jkt(t), ""); err != nil {
		t.Errorf("empty access token should skip ath, got %v", err)
	}
}

// stubReplayGuard lets tests force the guard's behavior.
type stubReplayGuard struct {
	fresh bool
	err   error
}

func (g stubReplayGuard) CheckAndRecord(context.Context, string, time.Time) (bool, error) {
	return g.fresh, g.err
}

func TestDPoPValidator_ReplayGuardFailsClosed(t *testing.T) {
	// A guard backend error must reject the proof (deny-by-default), surfaced
	// as ErrDPoPReplayBackend -- never silently treated as fresh.
	v := NewDPoPValidator(WithReplayGuard(stubReplayGuard{err: errors.New("redis down")}))
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPReplayBackend) {
		t.Errorf("expected ErrDPoPReplayBackend on guard failure, got %v", err)
	}
}

func TestDPoPValidator_ReplayGuardReplayRejected(t *testing.T) {
	// A guard reporting not-fresh yields ErrDPoPReplay.
	v := NewDPoPValidator(WithReplayGuard(stubReplayGuard{fresh: false}))
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "http://x/rpc"})
	_, err := v.validateString(context.Background(), proof, "POST", "http://x/rpc", b.jkt(t), "")
	if !errors.Is(err, ErrDPoPReplay) {
		t.Errorf("expected ErrDPoPReplay from guard, got %v", err)
	}
}

func TestDPoPValidator_URINormalization(t *testing.T) {
	// Default-port elision: proof signed for https://host matches request
	// URI https://host:443.
	v := NewDPoPValidator()
	b := newTestProofBuilder(t)
	proof := b.sign(proofOpts{htm: "POST", htu: "https://api.example.com/rpc"})
	if _, err := v.validateString(context.Background(), proof, "POST", "https://api.example.com:443/rpc", b.jkt(t), ""); err != nil {
		t.Errorf("default-port elision should match, got %v", err)
	}
}

func TestDPoPValidator_RejectMissingTyp(t *testing.T) {
	// A signer without typ=dpop+jwt produces a proof that must be rejected.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubJWK := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.ES256)}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithHeader("jwk", pubJWK),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	raw, err := josejwt.Signed(signer).Claims(map[string]any{
		"jti": "j",
		"htm": "POST",
		"htu": "http://x/rpc",
		"iat": time.Now().Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	v := NewDPoPValidator()
	_, err = v.validateString(context.Background(), raw, "POST", "http://x/rpc", "", "")
	if !errors.Is(err, ErrDPoPMalformed) {
		t.Errorf("expected ErrDPoPMalformed (missing typ), got %v", err)
	}
}

// TestReconstructRequestURI exercises the scheme/host/path reconstruction
// helper used by Validate() on live requests.
func TestReconstructRequestURI(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		path  string
		proto string
		tlsOn bool
		want  string
	}{
		{
			name: "plain http no forwarding",
			host: "api.example.com",
			path: "/rpc",
			want: "http://api.example.com/rpc",
		},
		{
			name:  "tls connection reports https",
			host:  "api.example.com",
			path:  "/rpc",
			tlsOn: true,
			want:  "https://api.example.com/rpc",
		},
		{
			name:  "x-forwarded-proto overrides",
			host:  "api.example.com",
			path:  "/rpc",
			proto: "https",
			want:  "https://api.example.com/rpc",
		},
		{
			name:  "x-forwarded-proto takes first entry only",
			host:  "api.example.com",
			path:  "/rpc",
			proto: "https, http",
			want:  "https://api.example.com/rpc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newFakeRequest(tt.host, tt.path, tt.proto, tt.tlsOn)
			got := reconstructRequestURI(r)
			if got != tt.want {
				t.Errorf("reconstructRequestURI = %q, want %q", got, tt.want)
			}
		})
	}
}
