package atoltest

import (
	"context"
	"os"
	"testing"

	sdk "atol.sh/sdk-go"
)

// Tuple represents an authorization relationship for test fixture setup.
type Tuple struct {
	User     string // e.g., "user:remi"
	Relation string // e.g., "editor"
	Object   string // e.g., "document:doc-123"
}

// Engine wraps *sdk.Atol with test-specific helpers. It embeds *sdk.Atol
// so all SDK methods (Check, Can, Authorize, GrantAccess, etc.) are
// available directly.
type Engine struct {
	*sdk.Atol
	tokens *TokenFactory
	t      testing.TB
}

// NewEngine creates a fully configured SDK instance for testing. No control
// plane connection, no background goroutines, no network I/O on the hot path.
// GrantAccess and RevokeAccess operate on the local in-memory store.
//
// Cleanup is automatic via t.Cleanup.
func NewEngine(t testing.TB, opts ...Option) *Engine {
	t.Helper()

	cfg := &engineConfig{}
	for _, o := range opts {
		o(cfg)
	}

	// Create or reuse token factory.
	var tf *TokenFactory
	ownedFactory := false
	if cfg.tokenFactory != nil {
		tf = cfg.tokenFactory
	} else {
		tf = NewTokenFactory(t)
		ownedFactory = true
	}

	// Create the SDK with local-only mode.
	sdkCfg := sdk.Config{
		JWKSUrl:  tf.JWKSUrl(),
		Issuer:   tf.Issuer(),
		Audience: cfg.audience,
	}

	atol, err := sdk.New(sdkCfg, sdk.WithLocalOnly())
	if err != nil {
		t.Fatalf("atoltest.NewEngine: %v", err)
	}

	// Load model if provided.
	if cfg.modelYAML != nil {
		if err := atol.LoadModel(cfg.modelYAML); err != nil {
			t.Fatalf("atoltest.NewEngine: load model: %v", err)
		}
	}
	if cfg.modelPath != "" {
		data, err := os.ReadFile(cfg.modelPath)
		if err != nil {
			t.Fatalf("atoltest.NewEngine: read model file %s: %v", cfg.modelPath, err)
		}
		if err := atol.LoadModel(data); err != nil {
			t.Fatalf("atoltest.NewEngine: load model from %s: %v", cfg.modelPath, err)
		}
	}

	// Load policy if provided.
	if cfg.policyBundle != nil {
		if err := atol.LoadBundle(cfg.policyBundle, cfg.policyData); err != nil {
			t.Fatalf("atoltest.NewEngine: load policy: %v", err)
		}
	}

	e := &Engine{Atol: atol, tokens: tf, t: t}

	// Pre-populate tuples.
	for _, tuple := range cfg.tuples {
		e.Grant(tuple.User, tuple.Relation, tuple.Object)
	}

	t.Cleanup(func() {
		atol.Close()
		if ownedFactory {
			tf.Close()
		}
	})

	return e
}

// Tokens returns the token factory for minting test JWTs. Tokens produced
// by this factory pass through the SDK's real TokenValidator.
func (e *Engine) Tokens() *TokenFactory {
	return e.tokens
}

// Grant writes a tuple directly to the local store. This is a convenience
// shorthand — no context or error handling needed. A store failure fails
// the test immediately.
func (e *Engine) Grant(user, relation, object string) {
	e.t.Helper()
	if err := e.ZanzibarEngine().WriteRawTuple(context.Background(), user, relation, object); err != nil {
		e.t.Fatalf("atoltest.Grant(%s, %s, %s): %v", user, relation, object, err)
	}
}

// Revoke deletes a tuple from the local store. A store failure fails the
// test immediately.
func (e *Engine) Revoke(user, relation, object string) {
	e.t.Helper()
	if err := e.ZanzibarEngine().DeleteRawTuple(context.Background(), user, relation, object); err != nil {
		e.t.Fatalf("atoltest.Revoke(%s, %s, %s): %v", user, relation, object, err)
	}
}

// GrantAll writes multiple tuples at once.
func (e *Engine) GrantAll(tuples []Tuple) {
	for _, t := range tuples {
		e.Grant(t.User, t.Relation, t.Object)
	}
}

// Option configures a test engine.
type Option func(*engineConfig)

type engineConfig struct {
	modelYAML    []byte
	modelPath    string
	tuples       []Tuple
	policyBundle []byte
	policyData   map[string]any
	audience     string
	tokenFactory *TokenFactory
}

// WithModel loads a Zanzibar authorization model from YAML bytes.
func WithModel(yaml []byte) Option {
	return func(c *engineConfig) { c.modelYAML = yaml }
}

// WithModelFile loads a Zanzibar authorization model from a file path.
func WithModelFile(path string) Option {
	return func(c *engineConfig) { c.modelPath = path }
}

// WithTuples pre-populates the store with the given tuples.
func WithTuples(tuples ...Tuple) Option {
	return func(c *engineConfig) { c.tuples = append(c.tuples, tuples...) }
}

// WithPolicy loads an OPA policy bundle with optional data.
func WithPolicy(bundleData []byte, policyData map[string]any) Option {
	return func(c *engineConfig) {
		c.policyBundle = bundleData
		c.policyData = policyData
	}
}

// WithTestAudience sets the expected JWT audience for token validation.
func WithTestAudience(aud string) Option {
	return func(c *engineConfig) { c.audience = aud }
}

// WithTokenFactory reuses an existing token factory instead of creating
// a new one. Useful when multiple engines share the same JWKS endpoint.
func WithTokenFactory(f *TokenFactory) Option {
	return func(c *engineConfig) { c.tokenFactory = f }
}
