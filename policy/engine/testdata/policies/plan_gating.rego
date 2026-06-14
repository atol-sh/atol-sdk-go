# Plan-gating fixture. The ReBAC relation grants access, but the
# subscription plan must also cover the action. Models the shape of
# a real customer policy: "only enterprise plan can invite users."
#
# Input schema (consistent across the SDK and the control plane):
#   input.user, input.relation, input.object -- the ReBAC triple.
#   input.plan                                -- subscription tier.
#   input.attrs.action                        -- the action being performed.
package atol

import rego.v1

default allow := false

allow if {
	zanzibar.check(input.user, input.relation, input.object)
	allowed_plan
}

allowed_plan if {
	input.plan == "enterprise"
}

allowed_plan if {
	input.attrs.action == "view"
	input.plan in {"starter", "pro", "enterprise"}
}
