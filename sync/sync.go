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
				c.setContinuationToken(newToken)
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

func (c *Client) setContinuationToken(token string) {
	c.mu.Lock()
	c.continuationToken = token
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

	c.logger.Info("sync stream connected",
		zap.String("org_id", c.orgID),
		zap.String("continuation_token", token))

	for stream.Receive() {
		msg := stream.Msg()

		if err := c.applyMutation(ctx, msg); err != nil {
			c.logger.Error("failed to apply mutation",
				zap.Error(err))
			// Continue processing; one bad mutation should not kill the stream.
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
		if m.PolicyBundleUpdate == nil || len(m.PolicyBundleUpdate.PolicyBundle) == 0 {
			return nil
		}
		return c.policy.LoadBundle(m.PolicyBundleUpdate.PolicyBundle, nil)

	case *apiv1.StreamMutationsResponse_PolicyDataUpdate:
		if m.PolicyDataUpdate == nil {
			return nil
		}
		path := m.PolicyDataUpdate.GetPath()
		if path == "" {
			return nil
		}
		var value interface{}
		if data := m.PolicyDataUpdate.GetData(); data != nil {
			value = data.AsMap()
		}
		c.logger.Debug("applying policy data update",
			zap.String("path", path))
		return c.policy.SetPolicyData(path, value)
	}

	return nil
}
