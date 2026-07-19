// Package engine provides the Go SDK's embeddable OPA+Zanzibar policy
// evaluation engine. The control plane implements the same public policy
// decision contract in its independently released engine.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"atol.sh/sdk-go/internal/safeconv"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/model"
)

// EvalInput holds the input for an authorization evaluation.
type EvalInput struct {
	User         string
	Relation     string
	Object       string
	ResourceType string
	ResourceID   string

	// ContextTuples are ephemeral tuples provided per-check that are overlaid
	// on the Zanzibar store for this evaluation only. Never persisted.
	ContextTuples []model.Tuple

	// Extra contains additional input fields passed to OPA evaluation.
	// These are merged into the OPA input map alongside the standard fields.
	Extra map[string]any
}

// EvalResult contains the outcome of an authorization evaluation.
type EvalResult struct {
	Allowed            bool
	MatchedRule        string
	Reason             string
	StepUp             *StepUp
	Trace              []string
	ZanzibarCalls      int32
	EvalUs             int32
	EvaluatedRulePaths []string
}

// StepUp describes an additional authentication step required.
type StepUp struct {
	Type   string
	Method string
}

// Engine provides embeddable OPA+Zanzibar policy evaluation.
//
// LoadBundle can be called concurrently with Evaluate (for example, a
// background goroutine fetching a new bundle while request handlers
// evaluate). The mu guards the *bundleState pointer so a reader always
// sees a consistent snapshot -- never half-installed bundle state.
type Engine struct {
	zanzibar *zanzibar.Engine

	mu     sync.RWMutex
	bundle *bundleState
}

// bundleState is one immutable bundle generation: the compiled modules,
// the data store, and a cache of prepared queries compiled against this
// exact (compiler, store) pair. Swapping bundles swaps the whole state,
// so prepared queries can never mix compiler-vN rules with store-vN+1
// data.
type bundleState struct {
	compiler *ast.Compiler
	store    storage.Store

	mu       sync.Mutex
	prepared map[string]*rego.PreparedEvalQuery
}

// preparedQuery returns the PreparedEvalQuery for the given query path,
// preparing and caching it on first use. Preparation happens once per
// query path per bundle generation -- the spec-required PreparedEvalQuery
// pattern that keeps the per-check hot path free of rego compilation.
func (bs *bundleState) preparedQuery(ctx context.Context, query string) (*rego.PreparedEvalQuery, error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if pq, ok := bs.prepared[query]; ok {
		return pq, nil
	}

	r := rego.New(
		rego.Query(query),
		rego.Compiler(bs.compiler),
		rego.Store(bs.store),
		rego.Function3(checkAccessDecl, dispatchCheckAccess),
		rego.StrictBuiltinErrors(true),
	)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare query %s: %w", query, err)
	}
	bs.prepared[query] = &pq
	return &pq, nil
}

// New creates a policy evaluation engine from a compiled OPA bundle and Zanzibar engine.
func New(zanzibarEngine *zanzibar.Engine) *Engine {
	return &Engine{
		zanzibar: zanzibarEngine,
	}
}

// LoadBundle compiles an OPA bundle (tar.gz bytes) and policy data into the engine.
func (e *Engine) LoadBundle(bundleData []byte, policyData map[string]any) error {
	reader := bundle.NewReader(bytes.NewReader(bundleData))
	b, err := reader.Read()
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	data := b.Data
	if data == nil {
		data = make(map[string]any)
	}

	// Overlay policy data.
	for path, value := range policyData {
		setNestedData(data, path, value)
	}

	// Compile modules with zanzibar.check built-in.
	modules := make(map[string]*ast.Module, len(b.Modules)+1)
	for _, m := range b.Modules {
		if m.Parsed.Package.Path.String() == policyDecisionPackage {
			return fmt.Errorf("compile rego: package %s is reserved", policyDecisionPackage)
		}
		modules[m.Path] = m.Parsed
	}
	runtimeModule, err := ast.ParseModule(policyDecisionModulePath, policyDecisionModule)
	if err != nil {
		return fmt.Errorf("parse policy decision adapter: %w", err)
	}
	modules[policyDecisionModulePath] = runtimeModule

	caps := ast.CapabilitiesForThisVersion()
	caps.Builtins = append(caps.Builtins, zanzibarCheckBuiltin())

	compiler := ast.NewCompiler().WithCapabilities(caps)
	compiler.Compile(modules)
	if compiler.Failed() {
		return fmt.Errorf("compile rego: %v", compiler.Errors)
	}

	// Swap the bundle state atomically so in-flight Evaluate calls
	// never see a half-installed bundle. Evaluate reads under RLock.
	// A fresh prepared-query cache comes with each generation.
	e.mu.Lock()
	e.bundle = &bundleState{
		compiler: compiler,
		store:    inmem.NewFromObject(data),
		prepared: make(map[string]*rego.PreparedEvalQuery),
	}
	e.mu.Unlock()
	return nil
}

// snapshot returns the current bundle state under the read lock, then
// releases it -- callers must use the snapshot without holding the lock
// so long evaluations don't block subsequent writers. Returns nil when
// no bundle has been loaded yet.
func (e *Engine) snapshot() *bundleState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bundle
}

// Evaluate runs an OPA+Zanzibar authorization evaluation.
//
// Error semantics: an undefined canonical decision means the
// loaded bundle has no opinion -- that falls back to a bare Zanzibar
// check (designed behavior). An evaluation ERROR (conflict, type error,
// cancelled context, ...) is surfaced to the caller as an error so it
// can deny and report -- it never silently degrades to the fallback.
func (e *Engine) Evaluate(ctx context.Context, input EvalInput) (*EvalResult, error) {
	// Pin a consistent bundle snapshot up front so we're immune to a
	// concurrent LoadBundle swapping half-way through.
	bs := e.snapshot()
	if bs == nil {
		return e.fallbackCheck(ctx, input)
	}

	start := time.Now()
	// Thread the caller-supplied ctx into evalState. The zanzibar.check
	// built-in reads it via s.evalCtx so tuple lookups land on the
	// correct tenant partition -- OPA's own bctx.Context drops context
	// values.
	state := &evalState{
		zanzibar:      e.zanzibar,
		contextTuples: input.ContextTuples,
		evalCtx:       ctx,
	}

	inputMap := maps.Clone(input.Extra)
	if inputMap == nil {
		inputMap = make(map[string]any)
	}
	// Standard authorization fields are authoritative. Extra context may add
	// policy inputs but must never spoof the principal, action, or resource
	// used by the Zanzibar check.
	maps.Copy(inputMap, map[string]any{
		"user":          input.User,
		"action":        input.Relation,
		"resource":      input.Object,
		"relation":      input.Relation,
		"object":        input.Object,
		"resource_type": input.ResourceType,
		"resource_id":   input.ResourceID,
	})

	rs, err := evalQuery(ctx, bs, state, policyDecisionQuery, inputMap)
	if err != nil {
		// Evaluation error: deny and surface. Never fall back.
		return nil, fmt.Errorf("opa eval %s (user %s, relation %s, object %s): %w",
			policyDecisionQuery, input.User, input.Relation, input.Object, err)
	}

	if !resultDefined(rs) {
		// Bundle loaded but no rule path is defined for this input --
		// the designed fallback to a bare Zanzibar check.
		return e.fallbackCheck(ctx, input)
	}

	decision, err := decodePolicyDecision(rs)
	if err != nil {
		return nil, fmt.Errorf("opa eval %s (user %s, relation %s, object %s): %w",
			policyDecisionQuery, input.User, input.Relation, input.Object, err)
	}

	evalUs, err := safeconv.SafeInt32From64(time.Since(start).Microseconds())
	if err != nil {
		return nil, fmt.Errorf("policy evaluation duration: %w", err)
	}
	trace := state.getTrace()
	trace = append(trace, fmt.Sprintf("opa.eval(%s -> %s) = structured allow=%v (%dus)", policyDecisionQuery, decision.MatchedRule, decision.Allowed, evalUs))
	decision.Trace = trace
	decision.ZanzibarCalls = state.calls.Load()
	decision.EvalUs = evalUs
	decision.EvaluatedRulePaths = []string{policyDecisionQuery}
	return decision, nil
}

// evalQuery is a package-level function rather than a method so the
// caller is forced to pin its own bundle snapshot via Engine.snapshot().
// That prevents a mid-evaluation bundle swap from mixing compiler-vN
// rules with store-vN+1 data.
//
// Per-evaluation state (context tuples, call counter, trace) travels to
// the zanzibar.check built-in through the eval context -- prepared
// queries capture their builtin implementation at prepare time, so the
// dispatch function recovers the state from ctx (see builtins.go).
func evalQuery(ctx context.Context, bs *bundleState, state *evalState, query string, input map[string]any) (rego.ResultSet, error) {
	pq, err := bs.preparedQuery(ctx, query)
	if err != nil {
		return nil, err
	}
	return pq.Eval(contextWithEvalState(ctx, state), rego.EvalInput(input))
}

func (e *Engine) fallbackCheck(ctx context.Context, input EvalInput) (*EvalResult, error) {
	start := time.Now()

	var allowed bool
	var err error
	if len(input.ContextTuples) > 0 {
		allowed, err = e.zanzibar.CheckWithContextTuples(ctx, input.User, input.Relation, input.Object, input.ContextTuples)
	} else {
		allowed, err = e.zanzibar.Check(ctx, input.User, input.Relation, input.Object)
	}
	if err != nil {
		return nil, fmt.Errorf("zanzibar check: %w", err)
	}

	evalUs, err := safeconv.SafeInt32From64(time.Since(start).Microseconds())
	if err != nil {
		return nil, fmt.Errorf("zanzibar evaluation duration: %w", err)
	}
	return &EvalResult{
		Allowed:       allowed,
		MatchedRule:   "zanzibar.check",
		Trace:         []string{fmt.Sprintf("zanzibar.check(%s, %s, %s) = %v", input.User, input.Relation, input.Object, allowed)},
		ZanzibarCalls: 1,
		EvalUs:        evalUs,
	}, nil
}

// SetPolicyData performs an incremental update of policy data in the OPA
// in-memory store. The path uses "/" as a separator (e.g. "atol/plan_features").
func (e *Engine) SetPolicyData(path string, value any) error {
	// Pin the bundle snapshot under the read lock -- LoadBundle may swap
	// the state concurrently, and reading e.bundle without the lock races.
	bs := e.snapshot()
	if bs == nil {
		return fmt.Errorf("policy engine store not initialized")
	}
	store := bs.store

	parts := strings.Split(path, "/")
	storagePath := make(storage.Path, len(parts))
	copy(storagePath, parts)

	ctx := context.Background()
	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("open write transaction: %w", err)
	}

	if _, err := store.Read(ctx, txn, storagePath); err != nil {
		if err := store.Write(ctx, txn, storage.AddOp, storagePath, value); err != nil {
			store.Abort(ctx, txn)
			return fmt.Errorf("write policy data: %w", err)
		}
	} else {
		if err := store.Write(ctx, txn, storage.ReplaceOp, storagePath, value); err != nil {
			store.Abort(ctx, txn)
			return fmt.Errorf("write policy data: %w", err)
		}
	}

	if err := store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("commit policy data: %w", err)
	}

	return nil
}

func setNestedData(data map[string]any, path string, value any) {
	parts := strings.Split(path, "/")
	current := data
	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part]
		if !ok {
			m := make(map[string]any)
			current[part] = m
			current = m
			continue
		}
		if m, ok := next.(map[string]any); ok {
			current = m
		} else {
			m := make(map[string]any)
			current[part] = m
			current = m
		}
	}
}

func resultDefined(rs rego.ResultSet) bool {
	return len(rs) > 0 && len(rs[0].Expressions) > 0
}
