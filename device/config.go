package device

// Config holds device intelligence configuration for the Atol SDK.
type Config struct {
	// Enabled turns on device context propagation in middleware.
	// When false, the device middleware is a no-op passthrough.
	Enabled bool

	// ControlPlaneURL is the Atol control plane base URL used for
	// device-related API calls (e.g., fetching device context by ID).
	// Defaults to the SDK's main ControlPlaneURL if empty.
	ControlPlaneURL string

	// APIKey is the API key for device intelligence API calls.
	// Defaults to the SDK's main KeyID if empty.
	APIKey string
}

// Defaults sets default values for zero-value fields.
func (c *Config) Defaults() {
	// No required defaults — all fields are either explicitly set or
	// inherited from the parent SDK config during Atol initialization.
}
