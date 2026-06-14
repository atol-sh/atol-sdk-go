package sdk

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

// newFakeRequest builds an http.Request with just enough shape for
// reconstructRequestURI.
func newFakeRequest(host, path, xForwardedProto string, tlsOn bool) *http.Request {
	r := &http.Request{
		Method: "POST",
		Host:   host,
		URL:    &url.URL{Path: path},
		Header: http.Header{},
	}
	if xForwardedProto != "" {
		r.Header.Set("X-Forwarded-Proto", xForwardedProto)
	}
	if tlsOn {
		r.TLS = &tls.ConnectionState{}
	}
	return r
}
