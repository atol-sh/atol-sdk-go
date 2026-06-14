# Session-age cap. Denies access when the session is older than the
# configured TTL, regardless of recent activity. Uses the same time
# inputs as auth_time_freshness but treats session creation as the
# cap-start rather than last-auth.
package atol

import rego.v1

default allow := false

# 8 hours in nanoseconds.
max_session_age_ns := 28800000000000

allow if {
	zanzibar.check(input.user, input.relation, input.object)
	session_within_cap
}

session_within_cap if {
	input.session_created_ns > 0
	input.now_ns - input.session_created_ns <= max_session_age_ns
}
