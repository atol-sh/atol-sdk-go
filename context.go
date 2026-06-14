package sdk

import (
	"context"

	"atol.sh/sdk-go/device"
)

// DeviceFromContext returns the device intelligence context for the current
// request. It is a convenience re-export of device.DeviceFromContext so callers
// can access device signals via a single top-level SDK import.
//
// Returns nil if device intelligence is not enabled or no device context has
// been populated by the device middleware. Callers must nil-check before use.
func DeviceFromContext(ctx context.Context) *device.DeviceContext {
	return device.DeviceFromContext(ctx)
}

// ContextWithDevice stores a DeviceContext in the request context. This is a
// convenience re-export of device.ContextWithDevice so tests and application
// code can populate device context without importing the device subpackage
// directly.
func ContextWithDevice(ctx context.Context, d *device.DeviceContext) context.Context {
	return device.ContextWithDevice(ctx, d)
}
