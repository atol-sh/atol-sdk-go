package sdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	"atol.sh/sdk-go/bootstrap"
	"atol.sh/sdk-go/decision"
	"atol.sh/sdk-go/device"
	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	hmacpkg "atol.sh/sdk-go/hmac"
	"atol.sh/sdk-go/internal/safeconv"
	policyengine "atol.sh/sdk-go/policy/engine"
	atolsync "atol.sh/sdk-go/sync"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// ErrAccessDenied is returned by Authorize when the request is denied.
var ErrAccessDenied = errors.New("access denied")

// Atol is the main SDK entry point. It embeds all three engines
// (Zanzibar, OPA, token validator) for in-process authorization.
type Atol struct {
	config           Config
	httpClient       *http.Client
	zanzibar         *zanzibar.Engine
	zanzibarStore    *store.MemoryStore
	policy           *policyengine.Engine
	validator        *TokenValidator
	sessionValidator *SessionValidator
	dpopValidator    *DPoPValidator
	decisionLogger   *decision.Logger
	materializers    *materializerRegistry
	tupleWriter      tupleWriter // strategy for GrantAccess/RevokeAccess persistence
	syncClient       *atolsync.Client
	syncCancel       context.CancelFunc
	drift            *device.DriftDetector // session-device drift detection; nil when device intelligence disabled
	logger           *zap.Logger
}

// tupleWriter abstracts tuple persistence so tests can write locally
// while production writes through to the control plane.
type tupleWriter interface {
	grant(ctx context.Context, user, relation, object string) error
	revoke(ctx context.Context, user, relation, object string) error
}

// remoteTupleWriter writes tuples to the control plane and mirrors locally.
type remoteTupleWriter struct {
	client  apiv1connect.AccessServiceClient
	storeID string
	zEngine *zanzibar.Engine
}

func (w *remoteTupleWriter) grant(ctx context.Context, user, relation, object string) error {
	_, err := w.client.GrantAccess(ctx, connect.NewRequest(&apiv1.GrantAccessRequest{
		OrgId:    w.storeID,
		User:     user,
		Relation: relation,
		Object:   object,
	}))
	if err != nil {
		return fmt.Errorf("grant access: %w", err)
	}
	if err := w.zEngine.WriteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("remote grant succeeded but local mirror failed for %s#%s@%s: %w", object, relation, user, err)
	}
	return nil
}

func (w *remoteTupleWriter) revoke(ctx context.Context, user, relation, object string) error {
	_, err := w.client.RevokeAccess(ctx, connect.NewRequest(&apiv1.RevokeAccessRequest{
		OrgId:    w.storeID,
		User:     user,
		Relation: relation,
		Object:   object,
	}))
	if err != nil {
		return fmt.Errorf("revoke access: %w", err)
	}
	if err := w.zEngine.DeleteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("remote revoke succeeded but local mirror failed for %s#%s@%s: %w", object, relation, user, err)
	}
	return nil
}

// localTupleWriter writes tuples directly to the in-memory store without
// contacting the control plane. Used by the atoltest package.
type localTupleWriter struct {
	zEngine *zanzibar.Engine
}

func (w *localTupleWriter) grant(ctx context.Context, user, relation, object string) error {
	if err := w.zEngine.WriteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("local grant: %w", err)
	}
	return nil
}

func (w *localTupleWriter) revoke(ctx context.Context, user, relation, object string) error {
	if err := w.zEngine.DeleteRawTuple(ctx, user, relation, object); err != nil {
		return fmt.Errorf("local revoke: %w", err)
	}
	return nil
}

// NewOption configures SDK construction.
type NewOption func(*newOptions)

type newOptions struct {
	localOnly bool
	logger    *zap.Logger
}

// WithLocalOnly creates an SDK instance that writes tuples directly to the
// local store without requiring a control plane connection. GrantAccess and
// RevokeAccess operate on the in-memory store only. Used by the atoltest
// package for testing.
func WithLocalOnly() NewOption {
	return func(o *newOptions) {
		o.localOnly = true
	}
}

// WithLogger sets the structured logger used by the SDK and all of its
// background components (sync client, session validator, decision logger).
// Defaults to zap.NewNop() when not provided -- but production deployments
// should always inject a real logger so background failures (CRL refresh,
// decision log flush, sync disconnects) are visible.
func WithLogger(logger *zap.Logger) NewOption {
	return func(o *newOptions) {
		o.logger = logger
	}
}

// NewHMACTransport returns an http.RoundTripper that HMAC-signs every
// outgoing request to the Atol control plane. Thin alias for
// hmac.NewTransport -- preserved here for callers that already import
// the top-level SDK package.
//
// New consumers (and any binary that also links proto-generated code
// from atol/platform) should import "atol.sh/sdk-go/hmac" directly. The
// hmac subpackage has zero proto dependencies, so it doesn't drag the
// SDK's generated registry in alongside the platform's.
func NewHMACTransport(keyID, secretKey string, base http.RoundTripper) http.RoundTripper {
	return hmacpkg.NewTransport(keyID, secretKey, base)
}

// New creates a new Atol SDK instance.
func New(config Config, opts ...NewOption) (*Atol, error) {
	var no newOptions
	for _, o := range opts {
		o(&no)
	}

	logger := no.logger
	if logger == nil {
		logger = zap.NewNop()
	}

	config.defaults()

	// Build an HTTP client that HMAC-signs requests to the control plane.
	httpClient := http.DefaultClient
	if config.KeyID != "" && config.SecretKey != "" {
		httpClient = &http.Client{
			Transport: hmacpkg.NewTransport(config.KeyID, config.SecretKey, http.DefaultTransport),
		}
	}

	zanzibarStore := store.NewMemoryStore()
	zanzibarEngine := zanzibar.New(zanzibarStore, nil, nil)
	policyEngine := policyengine.New(zanzibarEngine)

	// Load a local Zanzibar model file when configured. Bootstrap can still
	// replace it later with the control plane's model.
	if config.ZanzibarModelPath != "" {
		modelData, err := os.ReadFile(config.ZanzibarModelPath)
		if err != nil {
			return nil, fmt.Errorf("read zanzibar model %s: %w", config.ZanzibarModelPath, err)
		}
		if err := zanzibarEngine.LoadModel(modelData); err != nil {
			return nil, fmt.Errorf("load zanzibar model %s: %w", config.ZanzibarModelPath, err)
		}
	}

	var validator *TokenValidator
	if config.JWKSUrl != "" {
		validator = NewTokenValidator(config.JWKSUrl, config.Issuer, config.Audience)
	}

	// Initialize decision logger if control plane is configured.
	var decisionLogger *decision.Logger
	if config.ControlPlaneURL != "" && config.StoreID != "" {
		sink := decision.NewRPCSinkWithClient(config.ControlPlaneURL, config.StoreID, httpClient)
		decisionLogger = decision.NewLogger(
			sink,
			config.DecisionLogBufferSize,
			500, // Flush up to 500 entries per batch.
			config.DecisionLogFlushInterval,
			logger.Named("decision"),
		)
		decisionLogger.Start()
	}

	// Build tuple writer: local-only for testing, remote for production.
	var tw tupleWriter
	if no.localOnly {
		tw = &localTupleWriter{zEngine: zanzibarEngine}
	} else if config.ControlPlaneURL != "" {
		accessClient := apiv1connect.NewAccessServiceClient(httpClient, config.ControlPlaneURL)
		tw = &remoteTupleWriter{client: accessClient, storeID: config.StoreID, zEngine: zanzibarEngine}
	}

	// Session validator (CRL) — polls revoked sessions from the control plane
	// using the HMAC-authenticated client so polls succeed against the
	// API-key-required control plane.
	var sessionValidator *SessionValidator
	if config.ControlPlaneURL != "" && validator != nil {
		sessionValidator = NewSessionValidator(config.ControlPlaneURL, config.StoreID, 30*time.Second, httpClient, logger.Named("session_crl"))
		sessionValidator.Start()
	}

	// Session-device drift detector: detects when a token is presented from a
	// client whose live signals diverge from the device bound to the session
	// (e.g. a replayed bearer token from curl), and reports it to the control
	// plane. Only active when device intelligence is enabled.
	var driftDetector *device.DriftDetector
	if config.Device.Enabled && config.ControlPlaneURL != "" {
		dpClient := apiv1connect.NewDPAgentServiceClient(httpClient, config.ControlPlaneURL)
		driftDetector = device.NewDriftDetector(dpClient, device.DriftConfig{})
	}

	return &Atol{
		config:           config,
		httpClient:       httpClient,
		zanzibar:         zanzibarEngine,
		zanzibarStore:    zanzibarStore,
		policy:           policyEngine,
		validator:        validator,
		sessionValidator: sessionValidator,
		dpopValidator:    NewDPoPValidator(),
		decisionLogger:   decisionLogger,
		materializers:    newMaterializerRegistry(zanzibarStore),
		tupleWriter:      tw,
		drift:            driftDetector,
		logger:           logger,
	}, nil
}

// DriftDetector returns the session-device drift detector, or nil when device
// intelligence is disabled. Middleware uses it to flag replayed tokens.
func (a *Atol) DriftDetector() *device.DriftDetector {
	return a.drift
}

// Close gracefully shuts down the SDK, flushing any remaining decision logs.
func (a *Atol) Close() {
	if a.syncCancel != nil {
		a.syncCancel()
	}
	if a.sessionValidator != nil {
		a.sessionValidator.Stop()
	}
	if a.decisionLogger != nil {
		a.decisionLogger.Stop()
	}
}

// Logger returns the structured logger configured via WithLogger.
// Always non-nil -- defaults to zap.NewNop().
func (a *Atol) Logger() *zap.Logger {
	return a.logger
}

// DeviceConfig returns the device intelligence configuration.
// Use this when composing the device middleware:
//
//	mux.Use(middleware.DeviceMiddleware(engine.DeviceConfig()))
func (a *Atol) DeviceConfig() device.Config {
	return a.config.Device
}

// Validator returns the token validator, or nil if JWKS is not configured.
func (a *Atol) Validator() *TokenValidator {
	return a.validator
}

// SessionValidator returns the session CRL validator, or nil if not configured.
func (a *Atol) SessionValidator() *SessionValidator {
	return a.sessionValidator
}

// DPoPValidator returns the DPoP proof validator. Always non-nil -- the
// validator itself is cheap, and middleware branches on whether the
// incoming Authorization header uses the DPoP scheme.
func (a *Atol) DPoPValidator() *DPoPValidator {
	return a.dpopValidator
}

// RequireDPoP reports whether DPoP-bound tokens are mandatory. Middleware
// consults this to reject plain Bearer when the operator has opted in.
func (a *Atol) RequireDPoP() bool {
	return a.config.RequireDPoP
}

// Authorize checks if the current request (identified by the principal in context)
// is allowed to perform the given action on the given resource. It constructs a
// full OPA input map with all principal attributes, evaluates the policy, logs the
// decision, and returns a structured Decision. For successful evaluations (even
// denials), the caller checks decision.Err() or decision.Allow. Actual errors
// (no principal, evaluation failure) return (nil, err).
func (a *Atol) Authorize(ctx context.Context, action, resource string) (*Decision, error) {
	p, ok := UserFromContext(ctx)
	if !ok {
		a.logDecision("", action, resource, "", false, "no_principal", 0, 0)
		return nil, fmt.Errorf("no principal in context: %w", ErrAccessDenied)
	}

	resourceType, resourceID := parseObject(resource)

	// Build the enriched OPA input with all principal attributes.
	extra := map[string]interface{}{
		"org":          p.OrgID,
		"action":       action,
		"roles":        p.Roles,
		"plan":         p.Plan,
		"auth_method":  p.AuthMethod,
		"mfa_verified": p.MFAVerified,
		"trust_domain": p.TrustDomain,
		"client_ip":    p.ClientIP,
	}

	if !p.AuthTime.IsZero() {
		extra["auth_time_ns"] = p.AuthTime.UnixNano()
	}

	// Include identity info if available.
	if id, ok := IdentityFromContext(ctx); ok {
		extra["identity_id"] = id.ID
		extra["identity_scheme"] = id.Scheme
	}

	// Include device intelligence context if available.
	if dc := device.DeviceFromContext(ctx); dc != nil {
		extra = device.InjectOPAInput(extra, dc)
	}

	start := time.Now()
	result, err := a.policy.Evaluate(ctx, policyengine.EvalInput{
		User:         "user:" + p.UserID,
		Relation:     action,
		Object:       resource,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Extra:        extra,
	})
	evalUs, _ := safeconv.SafeInt32From64(time.Since(start).Microseconds())

	if err != nil {
		a.logDecision(p.UserID, action, resource, p.AuthMethod, false, "error", evalUs, 0)
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}

	a.logDecision(p.UserID, action, resource, p.AuthMethod, result.Allowed, result.MatchedRule, evalUs, result.ZanzibarCalls)

	d := &Decision{
		Allow:  result.Allowed,
		Reason: result.Reason,
	}
	if d.Reason == "" {
		d.Reason = result.MatchedRule
	}
	if result.StepUp != nil {
		d.StepUp = &StepUp{
			Type:   result.StepUp.Type,
			Method: result.StepUp.Method,
		}
	}
	return d, nil
}

// CheckOption configures a single authorization check.
type CheckOption func(*checkOptions)

type checkOptions struct {
	contextTuples []model.Tuple
}

// WithContextTuples provides ephemeral tuples that are overlaid on the Zanzibar
// store for this check only. Context tuples are never persisted or synced —
// they exist only for the duration of the evaluation. Use this for structural
// relationships the app already has in hand (e.g., profile → patient).
func WithContextTuples(tuples ...model.Tuple) CheckOption {
	return func(o *checkOptions) {
		o.contextTuples = append(o.contextTuples, tuples...)
	}
}

// Can checks if a user has a relation on an object.
// This is the primary authorization check — runs a full OPA eval with
// zanzibar.check() as a built-in, falling back to pure Zanzibar if
// no OPA bundle is loaded.
func (a *Atol) Can(ctx context.Context, user, relation, object string, opts ...CheckOption) (bool, error) {
	result, err := a.CanWithDetails(ctx, user, relation, object, opts...)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// CanWithDetails returns a full authorization decision with trace.
// Every evaluation through this path (Can, Check, CheckWithDetails) records
// a decision log entry when the decision logger is configured.
func (a *Atol) CanWithDetails(ctx context.Context, user, relation, object string, opts ...CheckOption) (*policyengine.EvalResult, error) {
	var o checkOptions
	for _, opt := range opts {
		opt(&o)
	}

	resourceType, resourceID := parseObject(object)
	start := time.Now()
	result, err := a.policy.Evaluate(ctx, policyengine.EvalInput{
		User:          user,
		Relation:      relation,
		Object:        object,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		ContextTuples: o.contextTuples,
	})
	evalUs, _ := safeconv.SafeInt32From64(time.Since(start).Microseconds())

	if a.decisionLogger != nil {
		authMethod := ""
		if p, ok := UserFromContext(ctx); ok {
			authMethod = p.AuthMethod
		}
		entry := decision.Entry{
			User:       strings.TrimPrefix(user, "user:"),
			Relation:   relation,
			Object:     object,
			AuthMethod: authMethod,
			EvalUs:     evalUs,
		}
		if err != nil {
			entry.Allowed = false
			entry.MatchedRule = "error"
		} else {
			entry.Allowed = result.Allowed
			entry.MatchedRule = result.MatchedRule
			entry.ZanzibarCalls = result.ZanzibarCalls
		}
		a.decisionLogger.Log(entry)
	}

	if err != nil {
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}
	return result, nil
}

// ZanzibarEngine returns the embedded Zanzibar engine for direct tuple operations.
// For tuple writes that need persistence, use GrantAccess/RevokeAccess instead.
func (a *Atol) ZanzibarEngine() *zanzibar.Engine {
	return a.zanzibar
}

// CheckDebug performs a Zanzibar check and returns a debug string explaining
// why it passed or failed (model state, tuple presence, etc.).
func (a *Atol) CheckDebug(ctx context.Context, user, relation, object string) (bool, string, error) {
	return a.zanzibar.CheckDebug(ctx, user, relation, object)
}

// GrantAccess writes an authorization tuple. In production, this persists to
// the control plane and mirrors locally. In local-only mode (WithLocalOnly),
// tuples are written directly to the in-memory store.
func (a *Atol) GrantAccess(ctx context.Context, user, relation, object string) error {
	if a.tupleWriter == nil {
		return fmt.Errorf("control plane not configured: set ControlPlaneURL")
	}
	return a.tupleWriter.grant(ctx, user, relation, object)
}

// RevokeAccess removes an authorization tuple. In production, this removes
// from the control plane and the local store. In local-only mode, tuples
// are deleted from the in-memory store only.
func (a *Atol) RevokeAccess(ctx context.Context, user, relation, object string) error {
	if a.tupleWriter == nil {
		return fmt.Errorf("control plane not configured: set ControlPlaneURL")
	}
	return a.tupleWriter.revoke(ctx, user, relation, object)
}

// RegisterMaterializer registers a callback that produces tuples from the app's
// own data source at bootstrap and on-demand. Materialized tuples live in SDK
// memory only — they are never sent to the control plane.
func (a *Atol) RegisterMaterializer(name string, fn MaterializerFunc) {
	a.materializers.register(name, fn)
}

// Materialize runs a single materializer by name, replacing its tuples in memory.
func (a *Atol) Materialize(ctx context.Context, name string) error {
	return a.materializers.materialize(ctx, name)
}

// MaterializeAll runs all registered materializers. Returns the first error
// encountered but continues running remaining materializers.
func (a *Atol) MaterializeAll(ctx context.Context) error {
	return a.materializers.materializeAll(ctx)
}

// LoadBundle loads an OPA policy bundle and data into the embedded engine.
func (a *Atol) LoadBundle(bundleData []byte, policyData map[string]interface{}) error {
	return a.policy.LoadBundle(bundleData, policyData)
}

// LoadModel loads a Zanzibar authorization model from YAML.
func (a *Atol) LoadModel(modelData []byte) error {
	return a.zanzibar.LoadModel(modelData)
}

// DecisionLogger returns the decision logger, or nil if not configured.
func (a *Atol) DecisionLogger() *decision.Logger {
	return a.decisionLogger
}

func parseObject(object string) (string, string) {
	for i, c := range object {
		if c == ':' {
			return object[:i], object[i+1:]
		}
	}
	return object, ""
}

// Bootstrap fetches the initial state (model, tuples, bundle, data) from the control plane.
func (a *Atol) Bootstrap(ctx context.Context) error {
	if a.config.ControlPlaneURL == "" {
		return fmt.Errorf("control plane URL not configured")
	}
	if a.config.StoreID == "" {
		return fmt.Errorf("store ID (org ID) not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, a.config.BootstrapTimeout)
	defer cancel()

	result, err := a.bootstrapLoad(ctx)
	if err != nil {
		return err
	}

	// Start live sync to receive real-time mutations from the control plane.
	if !a.config.DisableSync && result != nil && result.ContinuationToken != "" {
		a.syncClient = atolsync.NewClient(
			a.config.ControlPlaneURL,
			a.config.StoreID,
			result.ContinuationToken,
			a.httpClient,
			a.zanzibar,
			a.policy,
			a.logger.Named("sync"),
			atolsync.WithRebootstrap(a.rebootstrap),
		)
		syncCtx, cancel := context.WithCancel(context.Background())
		a.syncCancel = cancel
		go a.syncClient.Run(syncCtx)
	}

	return nil
}

// bootstrapLoad fetches the full state snapshot (model, tuples, bundle, data)
// from the control plane, loads it into the embedded engines, and runs all
// registered materializers.
func (a *Atol) bootstrapLoad(ctx context.Context) (*bootstrap.Result, error) {
	result, err := bootstrap.Bootstrap(ctx, a.config.ControlPlaneURL, a.config.StoreID, a.httpClient, a.zanzibar, a.policy)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// Run all registered materializers after bootstrap to populate SDK-local tuples.
	if err := a.materializers.materializeAll(ctx); err != nil {
		return nil, fmt.Errorf("materialize: %w", err)
	}

	return result, nil
}

// rebootstrap is the sync client's recovery path when the control plane
// refuses the continuation token: it re-runs the full bootstrap load and
// returns the fresh continuation token from the new snapshot.
func (a *Atol) rebootstrap(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.BootstrapTimeout)
	defer cancel()

	result, err := a.bootstrapLoad(ctx)
	if err != nil {
		return "", fmt.Errorf("rebootstrap: %w", err)
	}
	return result.ContinuationToken, nil
}

// logDecision records a decision log entry if the logger is configured.
func (a *Atol) logDecision(user, action, resource, authMethod string, allowed bool, matchedRule string, evalUs, zanzibarCalls int32) {
	if a.decisionLogger == nil {
		return
	}
	a.decisionLogger.Log(decision.Entry{
		User:          user,
		Relation:      action,
		Object:        resource,
		AuthMethod:    authMethod,
		Allowed:       allowed,
		MatchedRule:   matchedRule,
		EvalUs:        evalUs,
		ZanzibarCalls: zanzibarCalls,
	})
}
