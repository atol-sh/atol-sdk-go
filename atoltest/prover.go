package atoltest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
)

// DPoPProver mints DPoP proof JWTs signed by a fresh ES256 keypair, mirroring
// what the React SDK produces in the browser. Pair its JKT() with
// WithConfirmation to mint a matching sender-constrained token, then attach
// Proof(...) as the request's `DPoP` header so the SDK's DPoPValidator
// accepts the request end to end. Safe for concurrent use.
type DPoPProver struct {
	priv   *ecdsa.PrivateKey
	signer jose.Signer
	pubJWK jose.JSONWebKey
	jkt    string
}

// NewDPoPProver generates an ES256 keypair and returns a prover bound to it.
func NewDPoPProver() (*DPoPProver, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("atoltest: generate prover key: %w", err)
	}
	pubJWK := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.ES256)}
	jkt, err := jwkThumbprint(&pubJWK)
	if err != nil {
		return nil, fmt.Errorf("atoltest: prover thumbprint: %w", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: priv}},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		return nil, fmt.Errorf("atoltest: prover signer: %w", err)
	}
	return &DPoPProver{priv: priv, signer: signer, pubJWK: pubJWK, jkt: jkt}, nil
}

// JKT returns the RFC 7638 SHA-256 thumbprint (base64url, no padding) of the
// prover's public key -- the value to pass to WithConfirmation so the minted
// token's cnf.jkt matches the proofs this prover signs.
func (p *DPoPProver) JKT() string {
	return p.jkt
}

// Proof mints a DPoP proof JWT (typ=dpop+jwt, EmbedJWK) for the given HTTP
// method and absolute URL, with a fresh jti per call. When accessToken is
// non-empty it stamps `ath` = base64url(SHA-256(accessToken)) so the proof is
// bound to that token (RFC 9449 section 4.2). Pass "" to omit `ath` (e.g. for
// the token endpoint).
func (p *DPoPProver) Proof(method, url, accessToken string) (string, error) {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("atoltest: generate jti: %w", err)
	}
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jtiBytes),
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	tok, err := gojosejwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("atoltest: sign proof: %w", err)
	}
	return tok, nil
}

// jwkThumbprint returns the RFC 7638 SHA-256 thumbprint in base64url (no
// padding), matching dpop.go's jwkThumbprintSHA256 and the issuer's cnf.jkt.
func jwkThumbprint(key *jose.JSONWebKey) (string, error) {
	raw, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
