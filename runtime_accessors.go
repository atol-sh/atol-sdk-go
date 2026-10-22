package sdk

import (
	"go.uber.org/zap"

	"atol.sh/sdk-go/device"
)

// DriftDetector returns the session-device drift detector, or nil when device
// intelligence is disabled. Middleware uses it to flag replayed tokens.
func (a *Atol) DriftDetector() *device.DriftDetector {
	return a.drift
}

// Close gracefully shuts down the SDK, flushing any remaining decision logs.
func (a *Atol) Close() {
	if a.syncCancel != nil {
		a.syncCancel()
	}
	if a.bgCancel != nil {
		a.bgCancel()
	}
	if a.sessionValidator != nil {
		a.sessionValidator.Stop()
	}
	if a.decisionLogger != nil {
		a.decisionLogger.Stop()
	}
}

// Logger returns the structured logger configured via WithLogger.
// Always non-nil -- defaults to zap.NewNop().
func (a *Atol) Logger() *zap.Logger {
	return a.logger
}

// DeviceConfig returns the device intelligence configuration.
// Use this when composing the device middleware:
//
//	mux.Use(middleware.DeviceMiddleware(engine.DeviceConfig()))
func (a *Atol) DeviceConfig() device.Config {
	return a.config.Device
}

// Validator returns the token validator, or nil if JWKS is not configured.
func (a *Atol) Validator() *TokenValidator {
	return a.validator
}

// SessionValidator returns the session CRL validator, or nil if not configured.
func (a *Atol) SessionValidator() *SessionValidator {
	return a.sessionValidator
}

// DPoPValidator returns the DPoP proof validator. Always non-nil -- the
// validator itself is cheap, and middleware branches on whether the
// incoming Authorization header uses the DPoP scheme.
func (a *Atol) DPoPValidator() *DPoPValidator {
	return a.dpopValidator
}

// RequireDPoP reports whether DPoP-bound tokens are mandatory. Middleware
// consults this to reject plain Bearer when the operator has opted in.
func (a *Atol) RequireDPoP() bool {
	return a.config.RequireDPoP
}
