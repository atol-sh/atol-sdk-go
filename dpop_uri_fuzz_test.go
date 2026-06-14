package sdk

import (
	"net/http"
	"net/url"
	"testing"
)

// FuzzNormalizeDPoPURI stresses the htu canonicalizer. URL parsing is
// notoriously inconsistent across implementations; any input that
// produces a panic (rather than a stable string) is a bug.
func FuzzNormalizeDPoPURI(f *testing.F) {
	f.Add("http://example.com/rpc")
	f.Add("https://example.com:443/rpc")
	f.Add("http://example.com:80/rpc?foo=bar#frag")
	f.Add("not a url at all")
	f.Add("")
	f.Add("://missing.scheme")
	f.Add("http://[::1]:8080/")
	f.Add("http://user:pass@host.com/path?q=1#f")
	f.Add("\x00\x00\x00")
	f.Add("http://example.com/%GG") // invalid percent escape
	f.Add(string(make([]byte, 4096)))

	f.Fuzz(func(t *testing.T, raw string) {
		// Never panic. Return value type-checked by the compiler.
		_ = normalizeDPoPURI(raw)
	})
}

// FuzzReconstructRequestURI feeds arbitrary Host / Path / XFP into the
// request URI reconstructor. Same contract: no panics.
func FuzzReconstructRequestURI(f *testing.F) {
	f.Add("api.example.com", "/rpc", "")
	f.Add("api.example.com", "/rpc", "https")
	f.Add("", "", "")
	f.Add("host", "/", "https, http")
	f.Add("host:8080", "/a/b/c", "HTTPS")
	f.Add("host\x00", "/\x00", "\x00")
	f.Add(string(make([]byte, 256)), string(make([]byte, 512)), string(make([]byte, 128)))

	f.Fuzz(func(t *testing.T, host, path, xfp string) {
		r := &http.Request{
			Method: "POST",
			Host:   host,
			URL:    &url.URL{Path: path},
			Header: http.Header{},
		}
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		_ = reconstructRequestURI(r)
	})
}
