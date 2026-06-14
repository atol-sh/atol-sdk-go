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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
// For Connect streaming and gRPC content types the body hash is the
// empty-string hash (the server-side BodyHashMiddleware skips body
// reading for streams), so the transport mirrors that rule.
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
	ct := req.Header.Get("Content-Type")
	isStreaming := strings.Contains(ct, "connect+streaming") ||
		strings.Contains(ct, "grpc")

	var bodyBytes []byte
	if !isStreaming && req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("read request body for HMAC: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	bodyHash := sha256Hex(bodyBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := compute(t.secretKey, timestamp, req.Method, req.URL.Path, bodyHash)

	r := req.Clone(req.Context())
	r.Header.Set("Authorization", fmt.Sprintf(
		"ATOL-HMAC-SHA256 Credential=%s,Timestamp=%s,Signature=%s",
		t.keyID, timestamp, signature))
	if !isStreaming {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
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
