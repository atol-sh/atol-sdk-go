package device

import "net/http"

// headerDeviceID is the HTTP header set by the client JS SDK after
// device identification. It carries the stable device identifier.
const headerDeviceID = "X-Atol-Device-Id"

// HTTPMiddleware returns standard net/http middleware that extracts the
// device ID from the X-Atol-Device-Id header and stores a DeviceContext
// in the request context.
//
// This middleware is intentionally lightweight. The heavy lifting (signal
// collection, ML identification) happens client-side in the JS SDK. The
// Go middleware just propagates the device ID so authorization policies
// can reference it via input.device.
//
// When device intelligence is disabled (config.Enabled == false), the
// middleware passes requests through without modification.
func HTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			deviceID := r.Header.Get(headerDeviceID)
			if deviceID == "" {
				// No device ID header — proceed without device context.
				// This is not an error; not all clients use device intelligence.
				next.ServeHTTP(w, r)
				return
			}

			dc := &DeviceContext{
				DeviceID: deviceID,
			}

			ctx := ContextWithDevice(r.Context(), dc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
