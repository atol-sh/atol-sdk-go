package sdk

// Decision represents a structured authorization decision from OPA evaluation.
// It includes the allow/deny result, a human-readable reason, and optional
// step-up requirements (e.g., MFA, re-authentication).
type Decision struct {
	// Allow indicates whether the request is authorized.
	Allow bool

	// Reason provides a human-readable explanation for the decision.
	Reason string

	// StepUp indicates additional authentication required, or nil if none.
	StepUp *StepUp
}

// StepUp describes an additional authentication step required before access is granted.
type StepUp struct {
	// Type is the kind of step-up: "mfa", "reauth", or "passkey".
	Type string

	// Method is the specific method: "webauthn", "totp", "password", etc.
	Method string
}

// Err returns ErrAccessDenied if the decision is deny, nil if allow.
func (d *Decision) Err() error {
	if !d.Allow {
		return ErrAccessDenied
	}
	return nil
}
