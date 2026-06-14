package device

import (
	"net"
	"net/http"
	"strings"
)

// deviceIDHeader is the header the client JS SDK sets after device
// identification; its absence on an authenticated request that belongs to a
// fingerprinted session is itself a divergence signal.
const deviceIDHeader = "X-Atol-Device-Id"

// uaFamily reduces a User-Agent string to a coarse client family that can be
// compared against a device's stored browser_family. Browser families match the
// control plane's detectBrowserFamily output ("chrome", "firefox", "edge",
// "safari"); non-browser clients collapse to their tool name ("curl") or "cli".
func uaFamily(ua string) string {
	s := strings.ToLower(strings.TrimSpace(ua))
	if s == "" {
		return "cli"
	}
	switch {
	case strings.Contains(s, "edg/"), strings.Contains(s, "edge"):
		return "edge"
	case strings.Contains(s, "firefox"):
		return "firefox"
	case strings.Contains(s, "chrome"), strings.Contains(s, "chromium"):
		return "chrome"
	case strings.Contains(s, "safari") && strings.Contains(s, "applewebkit"):
		return "safari"
	}
	// Non-browser: take the tool name up to the first '/' or space (curl/8.7.1).
	if i := strings.IndexAny(s, "/ "); i > 0 {
		return s[:i]
	}
	return s
}

// isBrowserNavigation reports whether the request is a top-level browser
// navigation (a document load, e.g. opening or refreshing a page) rather than a
// script-initiated fetch/XHR. The client JS SDK only attaches the device-id
// header to its own fetch/XHR calls, never to document loads, so a navigation
// legitimately arrives without a fingerprint -- it must not be mistaken for a
// fingerprint-less replay.
//
// It keys off the Fetch Metadata request headers (Sec-Fetch-Mode/Dest), which
// every modern browser sends and which are forbidden headers that page
// JavaScript cannot set, so they cannot be spoofed by an in-page fetch.
func isBrowserNavigation(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return true
	}
	return strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "document")
}

// clientIP extracts the client IP from the request, honoring X-Forwarded-For
// (first hop) when present, otherwise the remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
