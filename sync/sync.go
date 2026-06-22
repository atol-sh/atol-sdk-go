// Package sync implements live mutation streaming from the Atol control plane.
// After bootstrap, a Client connects to StreamMutations and applies tuple
// writes/deletes, model updates, and policy bundle updates to the embedded
// Zanzibar and OPA engines in real time.
package sync

import (
	"context"
	"net/http"
	gosync "sync"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	policyengine "atol.sh/sdk-go/policy/engine"
	"atol.sh/sdk-go/zanzibar"
)

// RebootstrapFunc reloads the SDK's full state from the control plane
// (model, tuples, bundle, data) and returns a fresh continuation token.
// The sync client invokes it when the control plane refuses the offered
// continuation token (connect.CodeFailedPrecondition): the missed window
// can no longer be replayed, and incremental sync would silently run on
// stale state.
type RebootstrapFunc func(ctx context.Context) (continuationToken string, err error)

// Client streams mutations from the control plane and applies them to
// the embedded Zanzibar and policy engines. It reconnects automatically
// with exponential backoff on disconnect.
type Client struct {
	controlPlaneURL string
	orgID           string
	httpClient      *http.Client
	zanzibar        *zanzibar.Engine
	policy          *policyengine.Engine
	rebootstrap     RebootstrapFunc
	logger          *zap.Logger

	mu                gosync.Mutex
	continuationToken string

	// Freshness state (ADR 0018). All guarded by mu.
	//
	// connected reports whether a stream is currently open. lastStreamActivity
	// is a LOCAL clock reading set on stream open and on every successful
	// Receive -- it measures liveness ("the pipe is alive"), skew-free by
	// construction. lastAppliedServerTime is the SERVER clock decoded from the
	// newest continuation token's ULID -- it measures data age and is never
	// differenced against local now for gating. rebootstraps counts successful
	// rebootstraps.
	connected             bool
	lastStreamActivity    time.Time
	lastAppliedServerTime time.Time
	rebootstraps          int

	// Policy apply version guards (ADR 0022). All guarded by mu.
	//
	// lastBundleVersion is the version of the most recently applied policy
	// bundle. lastDataValue tracks the authoritative latest value per dynamic
	// data path, and lastDataVersion its version, so the SDK can drop stale
	// frames and re-overlay every tracked path after each bundle swap (which
	// rebuilds the data store from the bundle's own embedded data).
	lastBundleVersion int32
	lastDataVersion   map[string]int32
	lastDataValue     map[string]any
	// baselineData is the dynamic policy data loaded at bootstrap. It is
	// re-applied as the LoadBundle overlay on every bundle swap so a data-less
	// bundle activation does not silently wipe bootstrap-loaded dynamic data
	// (ADR 0022). Set via SeedPolicyData; guarded by mu.
	baselineData map[string]any
}

// Option configures a sync Client.
type Option func(*Client)

// WithRebootstrap sets the callback invoked when the control plane refuses
// the continuation token (connect.CodeFailedPrecondition: unparseable, too
// old, or replay window too large). Without it, a refused token stops the
// sync loop with an error log instead of retrying the same refused token
// forever.
func WithRebootstrap(fn RebootstrapFunc) Option {
	return func(c *Client) {
		c.rebootstrap = fn
	}
}

// NewClient creates a sync client that will stream mutations for the given
// org from the control plane and apply them to the local engines.
func NewClient(controlPlaneURL, orgID, continuationToken string, httpClient *http.Client, z *zanzibar.Engine, p *policyengine.Engine, logger *zap.Logger, opts ...Option) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	c := &Client{
		controlPlaneURL:   controlPlaneURL,
		orgID:             orgID,
		continuationToken: continuationToken,
		httpClient:        httpClient,
		zanzibar:          z,
		policy:            p,
		logger:            logger,
		lastDataVersion:   make(map[string]int32),
		lastDataValue:     make(map[string]any),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Run starts streaming mutations. It reconnects with exponential backoff
// on disconnect and blocks until ctx is cancelled. When the control plane
// refuses the continuation token it invokes the rebootstrap callback to
// reload state and obtain a fresh token; without a callback, a refused
// token stops the loop (retrying the same token can never succeed).
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tokenRefused, err := c.stream(ctx)
		if ctx.Err() != nil {
			return
		}

		if tokenRefused {
			if c.rebootstrap == nil {
				c.logger.Error("control plane refused continuation token and no rebootstrap callback is configured; sync stopped",
					zap.String("org_id", c.orgID),
					zap.Error(err))
				return
			}
			newToken, rbErr := c.rebootstrap(ctx)
			if rbErr != nil {
				c.logger.Error("rebootstrap failed; retrying",
					zap.String("org_id", c.orgID),
					zap.Error(rbErr))
				// Keep the refused token: the next attempt will be refused
				// again and re-trigger rebootstrap after backoff.
			} else {
				c.onRebootstrap(newToken)
				backoff = time.Second
				c.logger.Info("rebootstrap complete",
					zap.String("org_id", c.orgID),
					zap.String("continuation_token", newToken))
			}
		} else if err == nil {
			// Clean disconnect — reset backoff and reconnect immediately.
			backoff = time.Second
			continue
		} else {
			c.logger.Warn("sync stream disconnected, reconnecting",
				zap.Error(err),
				zap.Duration("backoff", backoff))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// ContinuationToken returns the latest continuation token received from
// the stream, which can be used for reconnecting or persisting state.
func (c *Client) ContinuationToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.continuationToken
}

// setContinuationToken stores the latest token and decodes its server-minted
// ULID time into lastAppliedServerTime (data age). A token that does not parse
// as a ULID (e.g. a synthetic empty-store cursor or a legacy token) leaves the
// server time zero rather than panicking.
func (c *Client) setContinuationToken(token string) {
	c.mu.Lock()
	c.continuationToken = token
	c.lastAppliedServerTime = tokenServerTime(token)
	c.mu.Unlock()
}

// tokenServerTime decodes the ULID timestamp from a continuation token. It
// returns the zero time on any parse failure -- never panics on caller-supplied
// or synthetic tokens.
func tokenServerTime(token string) time.Time {
	u, err := ulid.ParseStrict(token)
	if err != nil {
		return time.Time{}
	}
	return ulid.Time(u.Time())
}

// markStreamOpen records that a stream is open and refreshes the liveness clock.
func (c *Client) markStreamOpen() {
	c.mu.Lock()
	c.connected = true
	c.lastStreamActivity = time.Now()
	c.mu.Unlock()
}

// markStreamClosed records that the stream is no longer open. The liveness
// clock is left at its last observed value so the staleness gate can measure
// elapsed time since the pipe went quiet.
func (c *Client) markStreamClosed() {
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
}

// markActivity refreshes the liveness clock on a successful Receive.
func (c *Client) markActivity() {
	c.mu.Lock()
	c.lastStreamActivity = time.Now()
	c.mu.Unlock()
}

// onRebootstrap records a successful rebootstrap: the fresh token and a bumped
// rebootstrap counter.
func (c *Client) onRebootstrap(token string) {
	c.mu.Lock()
	c.continuationToken = token
	c.lastAppliedServerTime = tokenServerTime(token)
	c.rebootstraps++
	c.mu.Unlock()
}

// stream opens a single streaming connection and processes mutations until
// the stream ends or ctx is cancelled. The latest per-mutation continuation
// token is persisted on the client as it arrives, so reconnects resume from
// the last applied mutation. tokenRefused reports whether the control plane
// rejected the offered token (connect.CodeFailedPrecondition: re-bootstrap
// required), either at stream open or mid-stream.
func (c *Client) stream(ctx context.Context) (tokenRefused bool, err error) {
	token := c.ContinuationToken()

	client := apiv1connect.NewDPAgentServiceClient(c.httpClient, c.controlPlaneURL)

	stream, err := client.StreamMutations(ctx, connect.NewRequest(&apiv1.StreamMutationsRequest{
		OrgId:             c.orgID,
		ContinuationToken: token,
	}))
	if err != nil {
		return connect.CodeOf(err) == connect.CodeFailedPrecondition, err
	}
	defer stream.Close()

	c.markStreamOpen()
	defer c.markStreamClosed()

	c.logger.Info("sync stream connected",
		zap.String("org_id", c.orgID),
		zap.String("continuation_token", token))

	for stream.Receive() {
		// Liveness: a successful Receive means the pipe is alive, even on a
		// quiet stream that carries no mutation payload.
		c.markActivity()

		msg := stream.Msg()

		applyErr := c.applyMutation(ctx, msg)
		if applyErr != nil {
			// A genuine apply failure (store-not-initialized, malformed
			// bundle) must NOT advance the continuation token past an
			// unapplied policy change (ADR 0022). Surface it as a token
			// refusal so Run triggers the rebootstrap path; the token is
			// left at its last good value.
			c.logger.Error("failed to apply mutation; forcing rebootstrap",
				zap.String("org_id", c.orgID),
				zap.Error(applyErr))
			return true, applyErr
		}

		if msg.ContinuationToken != "" {
			c.setContinuationToken(msg.ContinuationToken)
		}
	}

	if err := stream.Err(); err != nil {
		return connect.CodeOf(err) == connect.CodeFailedPrecondition, err
	}
	return false, nil
}

func (c *Client) applyMutation(ctx context.Context, msg *apiv1.StreamMutationsResponse) error {
	switch m := msg.Mutation.(type) {
	case *apiv1.StreamMutationsResponse_TupleWrite:
		if m.TupleWrite == nil || m.TupleWrite.Tuple == nil {
			return nil
		}
		t := m.TupleWrite.Tuple
		return c.zanzibar.WriteTuple(ctx, t.User, t.Relation, t.Object)

	case *apiv1.StreamMutationsResponse_TupleDelete:
		if m.TupleDelete == nil || m.TupleDelete.Tuple == nil {
			return nil
		}
		t := m.TupleDelete.Tuple
		return c.zanzibar.DeleteTuple(ctx, t.User, t.Relation, t.Object)

	case *apiv1.StreamMutationsResponse_ModelUpdate:
		if m.ModelUpdate == nil || m.ModelUpdate.AuthorizationModel == "" {
			return nil
		}
		return c.zanzibar.LoadModel([]byte(m.ModelUpdate.AuthorizationModel))

	case *apiv1.StreamMutationsResponse_PolicyBundleUpdate:
		return c.applyPolicyBundle(m.PolicyBundleUpdate)

	case *apiv1.StreamMutationsResponse_PolicyDataUpdate:
		return c.applyPolicyData(m.PolicyDataUpdate)
	}

	return nil
}

// applyPolicyBundle applies a policy bundle update with the ADR 0022 version
// guard and the bundle-clobbers-data re-overlay. A version <= the last applied
// bundle is a correct no-op DROP (idempotent live/replay races, duplicate
// replays) and returns nil. A genuine LoadBundle failure returns an error so
// the caller forces a rebootstrap.
// SeedPolicyData records the dynamic policy data loaded at bootstrap so it is
// re-applied as the LoadBundle overlay on subsequent bundle swaps (ADR 0022),
// preventing a data-less bundle activation from wiping it. Call it before Run
// starts and again after every re-bootstrap.
func (c *Client) SeedPolicyData(data map[string]any) {
	c.mu.Lock()
	c.baselineData = data
	c.mu.Unlock()
}

func (c *Client) applyPolicyBundle(upd *apiv1.PolicyBundleUpdate) error {
	if upd == nil || len(upd.GetPolicyBundle()) == 0 {
		return nil
	}

	version := upd.GetVersion()
	c.mu.Lock()
	if version != 0 && version <= c.lastBundleVersion {
		c.mu.Unlock()
		c.logger.Debug("dropping stale policy bundle",
			zap.Int32("version", version),
			zap.Int32("last_applied", c.lastBundleVersion))
		return nil
	}
	// Snapshot the tracked dynamic data overlays under the lock so we can
	// re-apply them after the swap rebuilds the data store from the bundle's
	// own embedded data.
	overlays := make(map[string]any, len(c.lastDataValue))
	for path, value := range c.lastDataValue {
		overlays[path] = value
	}
	baseline := c.baselineData
	c.mu.Unlock()

	// Re-apply the bootstrap dynamic-data overlay first (reproducing what
	// Bootstrap did), then the per-path live overrides on top, so a bundle swap
	// never silently reverts bootstrap-loaded dynamic data (ADR 0022).
	if err := c.policy.LoadBundle(upd.GetPolicyBundle(), baseline); err != nil {
		return err
	}

	// Re-overlay every tracked dynamic data path: LoadBundle discarded them.
	for path, value := range overlays {
		if err := c.policy.SetPolicyData(path, value); err != nil {
			return err
		}
	}

	c.mu.Lock()
	c.lastBundleVersion = version
	c.mu.Unlock()
	return nil
}

// applyPolicyData applies a policy data update with the ADR 0022 version guard.
// A version <= the last applied for that path is a correct no-op DROP. The
// authoritative latest value and version are tracked so a subsequent bundle
// swap can re-overlay it.
func (c *Client) applyPolicyData(upd *apiv1.PolicyDataUpdate) error {
	if upd == nil {
		return nil
	}
	path := upd.GetPath()
	if path == "" {
		return nil
	}

	version := upd.GetVersion()
	c.mu.Lock()
	if version != 0 && version <= c.lastDataVersion[path] {
		c.mu.Unlock()
		c.logger.Debug("dropping stale policy data update",
			zap.String("path", path),
			zap.Int32("version", version),
			zap.Int32("last_applied", c.lastDataVersion[path]))
		return nil
	}
	c.mu.Unlock()

	var value any
	if data := upd.GetData(); data != nil {
		value = data.AsMap()
	}

	c.logger.Debug("applying policy data update",
		zap.String("path", path))
	if err := c.policy.SetPolicyData(path, value); err != nil {
		return err
	}

	c.mu.Lock()
	c.lastDataVersion[path] = version
	c.lastDataValue[path] = value
	c.mu.Unlock()
	return nil
}
