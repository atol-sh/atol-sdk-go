// Package policy provides policy generation utilities for the Atol authorization platform.
// GenerateDefaultPolicy produces an OPA bundle from a Zanzibar model so that customers
// who never write Rego get a working authorization policy out of the box.
package policy

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/bundle"

	"atol.sh/sdk-go/zanzibar/model"
)

// defaultRegoTemplate is the Rego source for the auto-generated default policy.
// It delegates every authorization decision to zanzibar.check(), implementing
// pure relationship-based access control. Customers can later replace this
// with custom Rego for ABAC/hybrid policies.
const defaultRegoTemplate = `# Auto-generated default policy for Atol.
# Delegates authorization decisions to the Zanzibar engine with temporal enforcement.
# Replace or extend this policy with custom Rego for ABAC/hybrid rules.
package atol

import rego.v1

default allow := false

# Allow if Zanzibar relationship exists AND no temporal or device restrictions block it.
allow if {
	not in_maintenance
	not resource_embargoed
	within_business_hours
	not device_blocked
	zanzibar.check(input.user, input.relation, input.object)
}

# Admins bypass maintenance windows but never bypass device blocks: a detected
# bot or high-anomaly session is denied even when presenting admin credentials.
allow if {
	in_maintenance
	input.org
	not device_blocked
	zanzibar.check(input.user, "admin", concat(":", ["org", input.org]))
}

# --- Device intelligence enforcement ---
# These rules only fire when the request carries device context (device
# intelligence enabled); without it they stay undefined and never block.

# Block requests from detected bots.
device_blocked if {
	input.device.signals.bot == true
}

# Block when the composite anomaly score exceeds the configured ceiling.
# No-op until data.atol.device_max_anomaly_score is set for the tenant.
device_blocked if {
	input.device.signals.anomaly_score > data.atol.device_max_anomaly_score
}

# --- Maintenance windows ---
# True when any active maintenance window covers the current time.
# Safe when no windows configured: no data.atol.maintenance_windows → rule doesn't fire.
in_maintenance if {
	window := data.atol.maintenance_windows[_]
	window.active == true
	time.now_ns() >= window.start_ns
	time.now_ns() <= window.end_ns
}

# --- Business hours ---
# Default: allowed (when no business hours config exists at all).
default within_business_hours := true

# Allowed when business hours are enabled AND we're within the configured window.
within_business_hours if {
	config := data.atol.business_hours
	config.enabled == true
	now := time.now_ns()
	day := time.weekday(now)
	config.days[_] == day
	clock := time.clock(now)
	hour := clock[0]
	hour >= config.start_hour
	hour < config.end_hour
}

# Allowed when business hours are explicitly disabled.
within_business_hours if {
	config := data.atol.business_hours
	config.enabled == false
}

# DENIED when business hours are enabled but we're outside the window.
# This overrides the default=true when config exists but conditions don't match.
within_business_hours := false if {
	config := data.atol.business_hours
	config.enabled == true
	not _in_business_window
}

_in_business_window if {
	config := data.atol.business_hours
	now := time.now_ns()
	day := time.weekday(now)
	config.days[_] == day
	clock := time.clock(now)
	hour := clock[0]
	hour >= config.start_hour
	hour < config.end_hour
}

# --- Resource embargoes ---
# True when the specific resource has an active embargo.
resource_embargoed if {
	embargo := data.atol.embargoes[input.resource_id]
	time.now_ns() >= embargo.start_ns
	time.now_ns() <= embargo.end_ns
}
`

// GenerateDefaultPolicy produces an OPA bundle (tar.gz bytes) containing a
// default Rego policy derived from the given Zanzibar authorization model.
// The generated policy delegates all authorization decisions to zanzibar.check(),
// providing pure ReBAC out of the box.
//
// If the model is nil or has no types, a minimal deny-all bundle is generated.
func GenerateDefaultPolicy(m *model.Model) ([]byte, error) {
	rego := generateRego(m)

	b := bundle.Bundle{
		Modules: []bundle.ModuleFile{
			{
				URL:  "/atol/authz/policy.rego",
				Path: "/atol/authz/policy.rego",
				Raw:  []byte(rego),
			},
		},
		Data: make(map[string]interface{}),
	}

	var buf bytes.Buffer
	if err := bundle.Write(&buf, b); err != nil {
		return nil, fmt.Errorf("write OPA bundle: %w", err)
	}

	return buf.Bytes(), nil
}

// GenerateDefaultRegoSource returns the raw Rego source string for the default
// policy. This is useful for displaying the generated policy in the dashboard
// without needing to unpack the OPA bundle.
func GenerateDefaultRegoSource(m *model.Model) string {
	return generateRego(m)
}

// generateRego builds the Rego source from the model. When the model contains
// types, it adds a comment listing the object types and their relations so
// that customers can see what their model covers.
func generateRego(m *model.Model) string {
	if m == nil || len(m.Types) == 0 {
		return defaultRegoTemplate
	}

	var sb strings.Builder
	sb.WriteString(defaultRegoTemplate)
	sb.WriteString("\n# ---- Model coverage ----\n")
	sb.WriteString("# Object types and relations derived from the Zanzibar model:\n")

	// Sort type names for deterministic output.
	typeNames := make([]string, 0, len(m.Types))
	for name := range m.Types {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)

	for _, typeName := range typeNames {
		typeDef := m.Types[typeName]
		if len(typeDef.Relations) == 0 {
			sb.WriteString(fmt.Sprintf("#   %s (no relations)\n", typeName))
			continue
		}

		relNames := make([]string, 0, len(typeDef.Relations))
		for relName := range typeDef.Relations {
			relNames = append(relNames, relName)
		}
		sort.Strings(relNames)

		sb.WriteString(fmt.Sprintf("#   %s: %s\n", typeName, strings.Join(relNames, ", ")))
	}

	return sb.String()
}
