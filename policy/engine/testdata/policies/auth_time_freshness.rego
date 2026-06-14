# auth_time freshness fixture. Access requires the user to have
# authenticated within the last 5 minutes -- pins the temporal
# enforcement path referenced in the OPA-zanzibar.check memory note.
#
# `input.auth_time_ns` and `input.now_ns` are both nanoseconds since
# the Unix epoch. The SDK populates auth_time_ns from the session and
# now_ns just before evaluation.
package atol

import rego.v1

default allow := false

# 300 seconds = 5 minutes, expressed in nanoseconds.
max_staleness_ns := 300000000000

allow if {
	zanzibar.check(input.user, input.relation, input.object)
	session_is_fresh
}

session_is_fresh if {
	input.auth_time_ns > 0
	input.now_ns - input.auth_time_ns <= max_staleness_ns
}
