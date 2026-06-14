package decision

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// sendTimeout bounds a single decision log batch send. Without it a hung
// control plane connection would pin the flush goroutine forever.
const sendTimeout = 10 * time.Second

// RPCSink sends decision log entries to the control plane via DPAgentService.
type RPCSink struct {
	client apiv1connect.DPAgentServiceClient
	orgID  string
}

// NewRPCSink creates a sink that streams decision logs to the given control plane URL.
func NewRPCSink(controlPlaneURL, orgID string) *RPCSink {
	return NewRPCSinkWithClient(controlPlaneURL, orgID, http.DefaultClient)
}

// NewRPCSinkWithClient creates a sink using the provided HTTP client for authentication.
func NewRPCSinkWithClient(controlPlaneURL, orgID string, httpClient *http.Client) *RPCSink {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client := apiv1connect.NewDPAgentServiceClient(
		httpClient,
		controlPlaneURL,
	)
	return &RPCSink{client: client, orgID: orgID}
}

// Send implements Sink by streaming entries to the DP Agent.
func (s *RPCSink) Send(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	stream := s.client.IngestDecisionLogs(ctx)
	for _, e := range entries {
		if err := stream.Send(&apiv1.IngestDecisionLogsRequest{
			Log: &apiv1.DecisionLog{
				OrgId:         s.orgID,
				RequestId:     e.RequestID,
				Timestamp:     timestamppb.New(e.Timestamp),
				ActorIdentity: e.User,
				AuthMethod:    e.AuthMethod,
				Action:        e.Relation,
				Resource:      e.Object,
				Allowed:       e.Allowed,
				MatchedRule:   e.MatchedRule,
				EvalUs:        e.EvalUs,
				ZanzibarCalls: e.ZanzibarCalls,
			},
		}); err != nil {
			return fmt.Errorf("send decision log: %w", err)
		}
	}

	if _, err := stream.CloseAndReceive(); err != nil {
		return fmt.Errorf("close decision log stream: %w", err)
	}
	return nil
}
