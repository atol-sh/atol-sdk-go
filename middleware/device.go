package middleware

import (
	"net/http"

	"atol.sh/sdk-go/device"
)

// DeviceMiddleware returns standard net/http middleware that extracts the
// device ID from the X-Atol-Device-Id header (set by the JS SDK after
// identification) and stores a DeviceContext in the request context.
//
// Chain this after HTTPMiddleware so that both the authenticated principal
// and the device context are available to authorization decisions:
//
//	mux.Use(middleware.HTTPMiddleware(engine))
//	mux.Use(middleware.DeviceMiddleware(engine.Config().Device))
//
// When device intelligence is disabled (config.Enabled == false), the
// middleware is a no-op passthrough.
func DeviceMiddleware(cfg device.Config) func(http.Handler) http.Handler {
	return device.HTTPMiddleware(cfg)
}
