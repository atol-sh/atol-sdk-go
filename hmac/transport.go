// Package hmac is a leaf package providing HMAC request signing for the
// Atol control plane. It deliberately does NOT import any proto-generated
// code so callers can use it without pulling the SDK's full type registry
// into their binary -- avoiding the "proto file is already registered"
// runtime panic that hits binaries which also link the platform's
// generated code.
package hmac

import (
	"bytes"
	stdhmac "crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// NewTransport returns an http.RoundTripper that HMAC-signs every outgoing
// request to the Atol control plane. The secret never crosses the wire --
// only the HMAC signature is sent in the Authorization header.
//
// The canonical envelope matches the server's verifier in
// atol/internal/auth/hmac.go::ComputeHMAC:
//
//	ATOL-HMAC-SHA256\n<unix-timestamp>\n<METHOD>\n<path>\n<sha256(body)-hex>
//
// Connect and gRPC streams use stream-hmac-v1: every request envelope is
// authenticated and chained, and an authenticated close frame prevents
// truncation. Unary HMAC remains byte-for-byte compatible.
//
// `base` may be nil; http.DefaultTransport is used in that case.
// `keyID` and `secretKey` are required -- empty strings produce
// verifiably-bad signatures the server will reject.
func NewTransport(keyID, secretKey string, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{keyID: keyID, secretKey: secretKey, base: base}
}

type transport struct {
	keyID     string
	secretKey string
	base      http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	isStreaming := IsStreamingContentType(req.Header.Get("Content-Type"))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	r := req.Clone(req.Context())

	if isStreaming {
		if req.Body == nil {
			return nil, fmt.Errorf("streaming HMAC request body is required")
		}
		nonceBytes := make([]byte, StreamNonceBytes)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, fmt.Errorf("generate streaming HMAC nonce: %w", err)
		}
		nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
		signature := ComputeStreamInit(t.secretKey, timestamp, req.Method, req.URL.Path, nonce)
		streamKey, err := DeriveStreamKey(t.secretKey, timestamp, req.Method, req.URL.Path, nonce)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", fmt.Sprintf(
			"ATOL-HMAC-SHA256 Credential=%s,Timestamp=%s,Signature=%s,Protocol=%s,Nonce=%s",
			t.keyID, timestamp, signature, StreamProtocol, nonce))
		r.Body = NewStreamBody(req.Context(), req.Body, streamKey)
		r.ContentLength = -1
		r.GetBody = nil
		r.Header.Del("Content-Length")
		return t.base.RoundTrip(r)
	}

	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body for HMAC: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	bodyHash := sha256Hex(bodyBytes)
	signature := compute(t.secretKey, timestamp, req.Method, req.URL.Path, bodyHash)

	r.Header.Set("Authorization", fmt.Sprintf(
		"ATOL-HMAC-SHA256 Credential=%s,Timestamp=%s,Signature=%s",
		t.keyID, timestamp, signature))
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))
	return t.base.RoundTrip(r)
}

// compute produces the HMAC-SHA256 hex signature for a request.
// String-to-sign: ATOL-HMAC-SHA256\n<ts>\n<method>\n<path>\n<body-sha256>.
func compute(secret, timestamp, method, path, bodyHash string) string {
	stringToSign := "ATOL-HMAC-SHA256\n" + timestamp + "\n" + method + "\n" + path + "\n" + bodyHash
	mac := stdhmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	return hex.EncodeToString(mac.Sum(nil))
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
