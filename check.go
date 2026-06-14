package sdk

import (
	"context"

	policyengine "atol.sh/sdk-go/policy/engine"
)

// Check is a convenience wrapper that uses the principal from context.
// Decision logging happens in CanWithDetails, the single evaluation path,
// so the logged MatchedRule is the actual query path the engine matched.
func (a *Atol) Check(ctx context.Context, relation, object string) (bool, error) {
	p, ok := UserFromContext(ctx)
	if !ok {
		return false, nil // No principal — deny by default.
	}
	return a.Can(ctx, "user:"+p.UserID, relation, object)
}

// CheckWithDetails returns detailed results using the principal from context.
func (a *Atol) CheckWithDetails(ctx context.Context, relation, object string) (*policyengine.EvalResult, error) {
	p, ok := UserFromContext(ctx)
	if !ok {
		return &policyengine.EvalResult{Allowed: false, MatchedRule: "no_principal"}, nil
	}
	return a.CanWithDetails(ctx, "user:"+p.UserID, relation, object)
}
