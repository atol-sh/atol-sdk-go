package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/model"
)

// zanzibarCheckBuiltin returns the ast.Builtin declaration for zanzibar.check.
func zanzibarCheckBuiltin() *ast.Builtin {
	return &ast.Builtin{
		Name: "zanzibar.check",
		Decl: types.NewFunction(types.Args(types.S, types.S, types.S), types.B),
	}
}

// checkAccessDecl declares the zanzibar.check(user, relation, object) built-in for rego.
var checkAccessDecl = &rego.Function{
	Name: "zanzibar.check",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.S),
		types.B,
	),
}

// evalStateKey is the context key carrying the per-evaluation state into
// the zanzibar.check built-in. Prepared queries capture their builtin
// implementation once at prepare time, so per-eval state cannot be bound
// via closure -- it travels through the eval context instead. OPA v1
// propagates ctx values into rego.BuiltinContext.Context (pinned by
// TestZanzibarCheckBuiltin_PreservesTenantContext).
type evalStateKey struct{}

// contextWithEvalState attaches the per-evaluation state to the context
// passed to PreparedEvalQuery.Eval.
func contextWithEvalState(ctx context.Context, s *evalState) context.Context {
	return context.WithValue(ctx, evalStateKey{}, s)
}

// dispatchCheckAccess is the builtin implementation registered with every
// prepared query. It recovers the per-evaluation state from the eval
// context and delegates to it. A missing state is a programmer error and
// fails the evaluation loudly rather than returning a fabricated result.
func dispatchCheckAccess(bctx rego.BuiltinContext, userTerm, relationTerm, objectTerm *ast.Term) (*ast.Term, error) {
	state, ok := bctx.Context.Value(evalStateKey{}).(*evalState)
	if !ok || state == nil {
		return nil, fmt.Errorf("zanzibar.check: no evaluation state in context (query evaluated outside Engine.Evaluate)")
	}
	return state.checkAccessFn(bctx, userTerm, relationTerm, objectTerm)
}

// evalState holds per-evaluation state for the zanzibar.check built-in.
type evalState struct {
	zanzibar      *zanzibar.Engine
	contextTuples []model.Tuple
	// evalCtx is the tenant-scoped context supplied by Engine.Evaluate,
	// preserved here so the built-in can read tuples with the correct
	// tenant partition.
	//
	// Current OPA v1 DOES propagate ctx.Value through bctx.Context, so
	// bctx.Context would also work today. We keep evalCtx as
	// defense-in-depth and to mirror the control-plane's zanzibar.check
	// built-in -- both implementations evolve together and either guards
	// against a future OPA version dropping context propagation (partial
	// eval, new scheduler, etc.).
	evalCtx context.Context
	calls   atomic.Int32
	trace   []string
	mu      sync.Mutex
}

// checkAccessFn implements the zanzibar.check(user, relation, object) built-in.
func (s *evalState) checkAccessFn(bctx rego.BuiltinContext, userTerm, relationTerm, objectTerm *ast.Term) (*ast.Term, error) {
	user, ok := userTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("zanzibar.check: user must be a string")
	}
	relation, ok := relationTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("zanzibar.check: relation must be a string")
	}
	object, ok := objectTerm.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("zanzibar.check: object must be a string")
	}

	// Prefer the tenant-scoped context from Engine.Evaluate. bctx.Context
	// is the OPA evaluator's context -- it won't carry the tenant key
	// because OPA doesn't thread context values through its eval pipeline.
	checkCtx := s.evalCtx
	if checkCtx == nil {
		checkCtx = bctx.Context
	}

	var allowed bool
	var err error
	if len(s.contextTuples) > 0 {
		allowed, err = s.zanzibar.CheckWithContextTuples(checkCtx, string(user), string(relation), string(object), s.contextTuples)
	} else {
		allowed, err = s.zanzibar.Check(checkCtx, string(user), string(relation), string(object))
	}
	s.calls.Add(1)

	if err != nil {
		s.mu.Lock()
		s.trace = append(s.trace, fmt.Sprintf("zanzibar.check(%s, %s, %s) = error: %v", user, relation, object, err))
		s.mu.Unlock()
		return ast.BooleanTerm(false), nil
	}

	s.mu.Lock()
	s.trace = append(s.trace, fmt.Sprintf("zanzibar.check(%s, %s, %s) = %v", user, relation, object, allowed))
	s.mu.Unlock()

	return ast.BooleanTerm(allowed), nil
}

// getTrace returns a copy of the accumulated trace entries.
func (s *evalState) getTrace() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.trace))
	copy(out, s.trace)
	return out
}
