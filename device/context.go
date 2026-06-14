// Package device provides device intelligence context management for the
// Atol SDK. It propagates device identification results (set by the client
// JS SDK) through the Go request context so that authorization policies
// can incorporate device trust signals.
package device

import "context"

type contextKey string

const deviceContextKey contextKey = "atol_device"

// DeviceContext holds the device intelligence results for the current request.
// The fields are populated by the client SDK's identification flow and
// propagated server-side via the X-Atol-Device-Id header.
type DeviceContext struct {
	// DeviceID is the stable device identifier assigned during identification.
	DeviceID string

	// Known indicates whether the device has been seen before (returning device).
	Known bool

	// Confidence is the ML-based match confidence score (0.0–1.0).
	Confidence float64

	// Signals contains smart signal results from the identification.
	// Nil when signals have not been evaluated.
	Signals *SmartSignals
}

// SmartSignals contains the boolean smart signal results and anomaly score
// from a device identification. These match the proto definition and the
// control plane's identification response.
type SmartSignals struct {
	Bot          bool
	VPN          bool
	Proxy        bool
	Tor          bool
	Incognito    bool
	Tampered     bool
	Emulator     bool
	Rooted       bool
	GeoMismatch  bool
	AnomalyScore float64
}

// ContextWithDevice stores a DeviceContext in the request context.
func ContextWithDevice(ctx context.Context, d *DeviceContext) context.Context {
	return context.WithValue(ctx, deviceContextKey, d)
}

// DeviceFromContext extracts the DeviceContext from the request context.
// Returns nil if no device context is present.
func DeviceFromContext(ctx context.Context) *DeviceContext {
	d, _ := ctx.Value(deviceContextKey).(*DeviceContext)
	return d
}
