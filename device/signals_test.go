package device

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:8080"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	r.Header.Set("X-Real-IP", "198.51.100.20")
	if got := clientIP(r); got != "10.0.0.1" {
		t.Errorf("clientIP() = %q, want direct peer 10.0.0.1", got)
	}
}
