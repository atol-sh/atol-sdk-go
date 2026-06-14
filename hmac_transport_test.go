package sdk_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	atol "atol.sh/sdk-go"
)

// TestNewHMACTransport_SignsCanonicalEnvelope drives a unary request through
// the public RoundTripper and verifies every field the server's
// AuthInterceptor reads:
//
//   - Authorization header has the ATOL-HMAC-SHA256 scheme with three
//     comma-separated key=value parts (Credential, Timestamp, Signature)
//   - Credential matches the supplied keyID
//   - Timestamp is recent (within 5s of now -- the verifier's skew window
//     is 5 minutes, but we want to know the transport stamps locally
//     rather than reusing a stale value)
//   - Signature is the HMAC of the canonical string
//     ATOL-HMAC-SHA256\n<ts>\n<method>\n<path>\n<sha256(body)>
func TestNewHMACTransport_SignsCanonicalEnvelope(t *testing.T) {
	const keyID = "atol_kid_test123"
	const secret = "test-secret-do-not-use"
	const path = "/atol.api.v1.OrgService/ListOrgs"
	body := []byte(`{"limit":10}`)

	var captured *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Re-read the body so we can verify the round-trip preserves it.
		buf, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(buf))
		captured = r
	}))
	defer srv.Close()

	client := &http.Client{Transport: atol.NewHMACTransport(keyID, secret, nil)}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/proto")
	if _, err := client.Do(req); err != nil {
		t.Fatalf("client.Do: %v", err)
	}

	auth := captured.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "ATOL-HMAC-SHA256 ") {
		t.Fatalf("Authorization scheme = %q, want ATOL-HMAC-SHA256 prefix", auth)
	}
	parts := splitHMAC(strings.TrimPrefix(auth, "ATOL-HMAC-SHA256 "))
	if parts["Credential"] != keyID {
		t.Errorf("Credential = %q, want %q", parts["Credential"], keyID)
	}
	ts, err := strconv.ParseInt(parts["Timestamp"], 10, 64)
	if err != nil {
		t.Fatalf("Timestamp not integer: %v", err)
	}
	if delta := time.Now().Unix() - ts; delta < 0 || delta > 5 {
		t.Errorf("Timestamp drift = %ds, want < 5s", delta)
	}

	// Recompute the signature locally and compare. Body hash is the SHA256
	// hex of the body bytes (matches internal/auth/hmac.go::ComputeHMAC).
	bodyHash := sha256Hex(body)
	wantSig := computeWantSig(secret, parts["Timestamp"], http.MethodPost, path, bodyHash)
	if !hmac.Equal([]byte(parts["Signature"]), []byte(wantSig)) {
		t.Errorf("Signature mismatch:\n  got:  %s\n  want: %s", parts["Signature"], wantSig)
	}
}

// TestNewHMACTransport_StreamingSkipsBodyHash mirrors the BodyHashMiddleware
// rule: when Content-Type is connect+streaming or grpc, the body hash is
// the empty-string hash (e3b0...) regardless of the actual body bytes.
// Without this, the server's verifier (which sets bodyHash =
// EmptyBodyHash for streaming) and the client would diverge and every
// stream would 401.
func TestNewHMACTransport_StreamingSkipsBodyHash(t *testing.T) {
	const path = "/atol.api.v1.DPAgentService/StreamMutations"
	const secret = "secret"

	cases := []struct{ name, contentType string }{
		{"connect-streaming", "application/connect+streaming+proto"},
		{"grpc", "application/grpc"},
		{"grpc-web", "application/grpc-web+proto"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured *http.Request
			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				captured = r
			}))
			defer srv.Close()

			client := &http.Client{Transport: atol.NewHMACTransport("kid", secret, nil)}
			req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader("any-body"))
			req.Header.Set("Content-Type", tc.contentType)
			if _, err := client.Do(req); err != nil {
				t.Fatalf("client.Do: %v", err)
			}

			parts := splitHMAC(strings.TrimPrefix(captured.Header.Get("Authorization"), "ATOL-HMAC-SHA256 "))
			emptyHash := sha256Hex(nil)
			wantSig := computeWantSig(secret, parts["Timestamp"], http.MethodPost, path, emptyHash)
			if parts["Signature"] != wantSig {
				t.Errorf("streaming signature should use EmptyBodyHash; got %s want %s",
					parts["Signature"], wantSig)
			}
		})
	}
}

// TestNewHMACTransport_NilBaseUsesDefault pins the documented default --
// callers may pass nil for the base RoundTripper and expect
// http.DefaultTransport to be used.
func TestNewHMACTransport_NilBaseUsesDefault(t *testing.T) {
	rt := atol.NewHMACTransport("kid", "secret", nil)
	if rt == nil {
		t.Fatal("NewHMACTransport returned nil")
	}
	// The transport must behave as a real round-tripper -- exercise it
	// against a httptest server. If `nil` had silently been retained as
	// `base`, RoundTrip would NPE.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip with nil base: %v", err)
	}
}

// TestNewHMACTransport_BodyPreserved ensures the body the server reads
// matches the body the caller wrote -- the transport must hash the body
// without consuming it.
func TestNewHMACTransport_BodyPreserved(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	var seen []byte
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	client := &http.Client{Transport: atol.NewHMACTransport("kid", "secret", nil)}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if _, err := client.Do(req); err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if !bytes.Equal(seen, body) {
		t.Errorf("body forwarded to server differs:\n  got:  %q\n  want: %q", seen, body)
	}
}

// --- Test helpers -- duplicated from atol.go intentionally because the
// production code keeps these unexported and we want the test to fail
// loudly if the wire envelope changes.

func splitHMAC(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	return out
}

func computeWantSig(secret, ts, method, path, bodyHash string) string {
	stringToSign := "ATOL-HMAC-SHA256\n" + ts + "\n" + method + "\n" + path + "\n" + bodyHash
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
