package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	policyDecisionPackage = "data.atol_internal_runtime"
	policyDecisionQuery   = policyDecisionPackage + ".decision"
	policyDecisionModule  = `package atol_internal_runtime

import rego.v1

decision := {"matched_rule": matched, "result": value} if {
	value := data.atol.access[input.resource_type].decision
	matched := sprintf("data.atol.access.%s.decision", [input.resource_type])
} else := {"matched_rule": "data.atol.decision", "result": value} if {
	value := data.atol.decision
} else := {"matched_rule": matched, "result": {"allow": value}} if {
	value := data.atol.access[input.resource_type].allow
	matched := sprintf("data.atol.access.%s.allow", [input.resource_type])
} else := {"matched_rule": "data.atol.allow", "result": {"allow": value}} if {
	value := data.atol.allow
}
`
	policyDecisionModulePath = "atol/internal/decision.rego"
)

// ErrInvalidPolicyDecision identifies a defined policy result that does not
// satisfy the public structured-decision contract.
var ErrInvalidPolicyDecision = errors.New("invalid policy decision")

func decodePolicyDecision(rs rego.ResultSet) (*EvalResult, error) {
	if !resultDefined(rs) {
		return nil, nil
	}

	envelope, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: adapter result must be an object", ErrInvalidPolicyDecision)
	}
	matchedRule, ok := envelope["matched_rule"].(string)
	if !ok || matchedRule == "" {
		return nil, fmt.Errorf("%w: adapter matched_rule must be a non-empty string", ErrInvalidPolicyDecision)
	}
	value, ok := envelope["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: result must be an object", ErrInvalidPolicyDecision)
	}

	allowed, ok := value["allow"].(bool)
	if !ok {
		return nil, fmt.Errorf("%w: allow must be a boolean", ErrInvalidPolicyDecision)
	}

	result := &EvalResult{Allowed: allowed, MatchedRule: matchedRule}
	if rawReason, exists := value["reason"]; exists {
		reason, reasonOK := rawReason.(string)
		if !reasonOK {
			return nil, fmt.Errorf("%w: reason must be a string", ErrInvalidPolicyDecision)
		}
		result.Reason = reason
	}

	if rawStepUp, exists := value["step_up"]; exists {
		stepUp, stepUpOK := rawStepUp.(map[string]any)
		if !stepUpOK {
			return nil, fmt.Errorf("%w: step_up must be an object", ErrInvalidPolicyDecision)
		}
		stepType, typeOK := stepUp["type"].(string)
		if !typeOK || strings.TrimSpace(stepType) == "" {
			return nil, fmt.Errorf("%w: step_up.type must be a non-empty string", ErrInvalidPolicyDecision)
		}

		method := ""
		if rawMethod, methodExists := stepUp["method"]; methodExists {
			var methodOK bool
			method, methodOK = rawMethod.(string)
			if !methodOK {
				return nil, fmt.Errorf("%w: step_up.method must be a string", ErrInvalidPolicyDecision)
			}
		}
		result.StepUp = &StepUp{Type: stepType, Method: method}
	}

	return result, nil
}
