# MFA-required fixture. The ReBAC check grants the base relation, but
# the decision returns a structured {allow, step_up} object when
# sensitive actions are requested without mfa_verified. This is the
# shape the SDK parses in parseStructuredDecision (engine.go:326).
package atol

import rego.v1

# Exposes a structured `decision` ({allow, step_up, reason}) so the
# SDK engine can surface a step-up requirement. The control-plane
# engine doesn't consume step_up yet (its EvalResult is bool-only);
# for that path, see mfa_required_bool.rego.
default decision := {"allow": false}

# Non-sensitive actions: straight pass-through.
decision := {"allow": true} if {
	input.attrs.action != "delete"
	zanzibar.check(input.user, input.relation, input.object)
}

# Sensitive action + MFA already verified: allow.
decision := {"allow": true} if {
	input.attrs.action == "delete"
	input.mfa_verified == true
	zanzibar.check(input.user, input.relation, input.object)
}

# Sensitive action + no MFA: emit step_up.
decision := {
	"allow": false,
	"step_up": {"type": "mfa", "method": "passkey"},
	"reason": "sensitive action requires MFA",
} if {
	input.attrs.action == "delete"
	input.mfa_verified != true
	zanzibar.check(input.user, input.relation, input.object)
}
