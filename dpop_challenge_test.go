package sdk

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteDPoPChallenge_Default(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDPoPChallenge(w, nil)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
	got := w.Header().Get("WWW-Authenticate")
	want := `DPoP algs="ES256 ES384 ES512 PS256 RS256"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	if strings.Contains(got, "error=") {
		t.Errorf("default challenge must not carry an error code: %q", got)
	}
}

func TestWriteDPoPChallenge_InvalidProof(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDPoPChallenge(w, nil, WithInvalidProofError())

	got := w.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, "DPoP ") {
		t.Errorf("scheme = %q, want DPoP prefix", got)
	}
	if !strings.Contains(got, `error="invalid_dpop_proof"`) {
		t.Errorf("WWW-Authenticate = %q, want invalid_dpop_proof", got)
	}
	if !strings.Contains(got, `algs="`) {
		t.Errorf("WWW-Authenticate = %q, want algs param", got)
	}
}

func TestWriteDPoPChallenge_CustomAlgs(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDPoPChallenge(w, []string{"ES256"})

	got := w.Header().Get("WWW-Authenticate")
	if got != `DPoP algs="ES256"` {
		t.Errorf("WWW-Authenticate = %q, want DPoP algs=\"ES256\"", got)
	}
}

func TestWriteDPoPChallenge_Nonce(t *testing.T) {
	w := httptest.NewRecorder()
	WriteDPoPChallenge(w, nil, WithDPoPNonce("nonce-123"))

	got := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(got, `error="use_dpop_nonce"`) {
		t.Errorf("WWW-Authenticate = %q, want use_dpop_nonce", got)
	}
	if n := w.Header().Get("DPoP-Nonce"); n != "nonce-123" {
		t.Errorf("DPoP-Nonce = %q, want nonce-123", n)
	}
}
