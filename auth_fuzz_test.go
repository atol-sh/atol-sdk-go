package sdk

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// FuzzParseJWTToken exercises the first step of token validation --
// josejwt.ParseSigned -- against arbitrary bytes. The caller code in
// ValidateToken ignores any parse error, but a panic inside go-jose
// on a crafted input is a real crash we want to surface.
func FuzzParseJWTToken(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("\x00.\x00.\x00")
	f.Add("not.a.jwt.at.all.yes.no")
	f.Add(string(make([]byte, 4096)))

	algs := []jose.SignatureAlgorithm{jose.RS256}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = josejwt.ParseSigned(raw, algs)
	})
}

// FuzzValidateTokenDoesNotPanic feeds arbitrary tokens through the full
// ValidateToken pipeline with a real validator. The validator will
// always error (no JWKS configured), but the pipeline must not panic.
func FuzzValidateTokenDoesNotPanic(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig")
	f.Add("")
	f.Add("Bearer without-scheme-removed")
	f.Add("a.b.c.d.e")
	f.Add(string(make([]byte, 2048)))

	// Validator with a dead JWKS URL so the FindKey call returns quickly.
	v := NewTokenValidator("http://127.0.0.1:1/jwks", "http://127.0.0.1:1", "")
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, raw string) {
		// Caller must not panic even when JWKS lookup fails or the token
		// is gibberish.
		_, _, _, _, _ = v.ValidateToken(ctx, raw)
	})
}
