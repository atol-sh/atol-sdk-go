package atoltest_test

import (
	"context"
	"net/http/httptest"
	"testing"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
)

// TestProverAcceptedByValidator is the SDK-2 acceptance test: a token minted
// WithConfirmation(prover.JKT()) plus a proof from prover.Proof(...) passes the
// SDK's DPoPValidator end to end; wrong key, wrong method, wrong uri, and
// replay each fail.
func TestProverAcceptedByValidator(t *testing.T) {
	tf := atoltest.NewTokenFactory(t)
	prover, err := atoltest.NewDPoPProver()
	if err != nil {
		t.Fatalf("NewDPoPProver: %v", err)
	}

	const url = "https://api.example.com/rpc"
	token := tf.MintToken(
		atoltest.WithSubject("remi"),
		atoltest.WithTokenType("at+jwt"),
		atoltest.WithConfirmation(prover.JKT()),
	)

	// Confirm the token validates and carries cnf.jkt == prover.JKT().
	v := sdk.NewTokenValidator(tf.JWKSUrl(), tf.Issuer(), "", sdk.WithRequiredTokenType("at+jwt"))
	_, _, claims, _, err := v.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Cnf == nil || claims.Cnf.JKT != prover.JKT() {
		t.Fatalf("cnf.jkt = %v, want %q", claims.Cnf, prover.JKT())
	}

	dv := sdk.NewDPoPValidator()

	// Happy path: fresh proof for the right method/url/token.
	proof, err := prover.Proof("POST", url, token)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	r := httptest.NewRequest("POST", url, nil)
	r.Header.Set("DPoP", proof)
	if _, err := dv.Validate(r, prover.JKT(), token); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}

	// Wrong key: a different prover's proof must fail the jkt binding.
	other, err := atoltest.NewDPoPProver()
	if err != nil {
		t.Fatalf("NewDPoPProver(other): %v", err)
	}
	otherProof, _ := other.Proof("POST", url, token)
	rw := httptest.NewRequest("POST", url, nil)
	rw.Header.Set("DPoP", otherProof)
	if _, err := dv.Validate(rw, prover.JKT(), token); err == nil {
		t.Error("wrong key: expected rejection, got nil")
	}

	// Wrong method: proof htm=POST presented on a GET request.
	pm, _ := prover.Proof("POST", url, token)
	rm := httptest.NewRequest("GET", url, nil)
	rm.Header.Set("DPoP", pm)
	if _, err := dv.Validate(rm, prover.JKT(), token); err == nil {
		t.Error("wrong method: expected rejection, got nil")
	}

	// Wrong uri: proof htu differs from request URI.
	pu, _ := prover.Proof("POST", "https://api.example.com/other", token)
	ru := httptest.NewRequest("POST", url, nil)
	ru.Header.Set("DPoP", pu)
	if _, err := dv.Validate(ru, prover.JKT(), token); err == nil {
		t.Error("wrong uri: expected rejection, got nil")
	}

	// Replay: reusing the same proof (same jti) must fail the second time.
	replay, _ := prover.Proof("POST", url, token)
	r1 := httptest.NewRequest("POST", url, nil)
	r1.Header.Set("DPoP", replay)
	if _, err := dv.Validate(r1, prover.JKT(), token); err != nil {
		t.Fatalf("replay first use: %v", err)
	}
	r2 := httptest.NewRequest("POST", url, nil)
	r2.Header.Set("DPoP", replay)
	if _, err := dv.Validate(r2, prover.JKT(), token); err == nil {
		t.Error("replay: expected rejection on reuse, got nil")
	}
}

// TestRequiredTokenType is the SDK-1 acceptance test: at+jwt passes when
// required; a plain "JWT" typ is rejected when at+jwt is required; both pass
// when the requirement is unset.
func TestRequiredTokenType(t *testing.T) {
	tf := atoltest.NewTokenFactory(t)

	atJWT := tf.MintToken(atoltest.WithSubject("a"), atoltest.WithTokenType("at+jwt"))
	plainJWT := tf.MintToken(atoltest.WithSubject("b"), atoltest.WithTokenType("JWT"))
	noTyp := tf.MintToken(atoltest.WithSubject("c"))

	strict := sdk.NewTokenValidator(tf.JWKSUrl(), tf.Issuer(), "", sdk.WithRequiredTokenType("at+jwt"))
	if _, _, _, _, err := strict.ValidateToken(context.Background(), atJWT); err != nil {
		t.Errorf("at+jwt should pass strict validator: %v", err)
	}
	if _, _, _, _, err := strict.ValidateToken(context.Background(), plainJWT); err == nil {
		t.Error("JWT typ should be rejected when at+jwt required")
	}
	if _, _, _, _, err := strict.ValidateToken(context.Background(), noTyp); err == nil {
		t.Error("missing typ should be rejected when at+jwt required")
	}

	lax := sdk.NewTokenValidator(tf.JWKSUrl(), tf.Issuer(), "")
	if _, _, _, _, err := lax.ValidateToken(context.Background(), atJWT); err != nil {
		t.Errorf("at+jwt should pass lax validator: %v", err)
	}
	if _, _, _, _, err := lax.ValidateToken(context.Background(), plainJWT); err != nil {
		t.Errorf("JWT typ should pass lax validator: %v", err)
	}
	if _, _, _, _, err := lax.ValidateToken(context.Background(), noTyp); err != nil {
		t.Errorf("missing typ should pass lax validator: %v", err)
	}
}
