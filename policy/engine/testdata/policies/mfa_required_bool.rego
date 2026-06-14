# Boolean MFA fixture for evaluators that only consume `allow`
# (the control-plane engine today). Encodes the same semantics as
# mfa_required.rego -- sensitive action + unverified MFA => deny --
# but without the structured step_up payload. Both fixtures MUST stay
# semantically equivalent on the allow/deny axis.
package atol

import rego.v1

default allow := false

# Non-sensitive: allow if the ReBAC relation holds.
allow if {
	input.attrs.action != "delete"
	zanzibar.check(input.user, input.relation, input.object)
}

# Sensitive + MFA verified: allow.
allow if {
	input.attrs.action == "delete"
	input.mfa_verified == true
	zanzibar.check(input.user, input.relation, input.object)
}

# Sensitive + no MFA: falls through to the default (deny).
