// Package bootstrap implements SDK state initialization from the control plane.
package bootstrap

import (
	"context"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"go.opentelemetry.io/otel"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	policyengine "atol.sh/sdk-go/policy/engine"
	"atol.sh/sdk-go/zanzibar"
)

// Result contains the bootstrap state and continuation token.
type Result struct {
	ContinuationToken string
}

// Bootstrap fetches state from the control plane and loads it into the engines.
func Bootstrap(ctx context.Context, controlPlaneURL, orgID string, httpClient *http.Client, zanzibarEngine *zanzibar.Engine, policyEngine *policyengine.Engine) (*Result, error) {
	ctx, span := otel.Tracer("atol-sdk").Start(ctx, "sdk.Bootstrap")
	defer span.End()

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Create Connect-go client for DPAgentService.
	client := apiv1connect.NewDPAgentServiceClient(
		httpClient,
		controlPlaneURL,
	)

	// Fetch bootstrap snapshot.
	resp, err := client.GetBootstrapSnapshot(ctx, connect.NewRequest(&apiv1.GetBootstrapSnapshotRequest{
		OrgId: orgID,
	}))
	if err != nil {
		return nil, fmt.Errorf("get bootstrap snapshot: %w", err)
	}

	snap := resp.Msg

	// Load authorization model.
	if snap.AuthorizationModel != "" {
		if err := zanzibarEngine.LoadModel([]byte(snap.AuthorizationModel)); err != nil {
			return nil, fmt.Errorf("load authorization model: %w", err)
		}
	}

	// Load tuples into Zanzibar engine.
	// Proto tuples use "type:id" format for User and Object, matching WriteTuple's API.
	for _, t := range snap.Tuples {
		if err := zanzibarEngine.WriteTuple(ctx, t.User, t.Relation, t.Object); err != nil {
			return nil, fmt.Errorf("write tuple: %w", err)
		}
	}

	// Load policy bundle.
	if len(snap.PolicyBundle) > 0 {
		var policyData map[string]any
		if snap.PolicyData != nil {
			policyData = snap.PolicyData.AsMap()
		}
		if err := policyEngine.LoadBundle(snap.PolicyBundle, policyData); err != nil {
			return nil, fmt.Errorf("load policy bundle: %w", err)
		}
	}

	return &Result{
		ContinuationToken: snap.ContinuationToken,
	}, nil
}
