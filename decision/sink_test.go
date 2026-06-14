package decision

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
)

// capturedLog holds the fields from a received DecisionLog for test assertions.
type capturedLog struct {
	OrgID         string
	RequestID     string
	ActorIdentity string
	AuthMethod    string
	Action        string
	Resource      string
	Allowed       bool
	MatchedRule   string
	EvalUs        int32
	ZanzibarCalls int32
	HasTimestamp  bool
}

// mockIngestHandler implements the DPAgentService IngestDecisionLogs RPC
// and captures all received log entries for assertion.
type mockIngestHandler struct {
	apiv1connect.UnimplementedDPAgentServiceHandler

	mu       sync.Mutex
	received []capturedLog
}

func (m *mockIngestHandler) IngestDecisionLogs(_ context.Context, stream *connect.ClientStream[apiv1.IngestDecisionLogsRequest]) (*connect.Response[apiv1.IngestDecisionLogsResponse], error) {
	var accepted int32
	for stream.Receive() {
		log := stream.Msg().GetLog()
		if log == nil {
			continue
		}
		m.mu.Lock()
		m.received = append(m.received, capturedLog{
			OrgID:         log.GetOrgId(),
			RequestID:     log.GetRequestId(),
			ActorIdentity: log.GetActorIdentity(),
			AuthMethod:    log.GetAuthMethod(),
			Action:        log.GetAction(),
			Resource:      log.GetResource(),
			Allowed:       log.GetAllowed(),
			MatchedRule:   log.GetMatchedRule(),
			EvalUs:        log.GetEvalUs(),
			ZanzibarCalls: log.GetZanzibarCalls(),
			HasTimestamp:  log.GetTimestamp() != nil,
		})
		m.mu.Unlock()
		accepted++
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&apiv1.IngestDecisionLogsResponse{
		Accepted: accepted,
		Rejected: 0,
	}), nil
}

func (m *mockIngestHandler) logs() []capturedLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capturedLog, len(m.received))
	copy(out, m.received)
	return out
}

func TestRPCSink_Send(t *testing.T) {
	t.Parallel()

	mock := &mockIngestHandler{}
	path, handler := apiv1connect.NewDPAgentServiceHandler(mock)

	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tests := []struct {
		name    string
		orgID   string
		entries []Entry
	}{
		{
			name:  "single allow entry",
			orgID: "org-test-1",
			entries: []Entry{
				{
					RequestID:     "req-001",
					User:          "user:alice",
					Relation:      "read",
					Object:        "document:readme",
					Allowed:       true,
					MatchedRule:   "zanzibar.check",
					EvalUs:        42,
					ZanzibarCalls: 1,
					AuthMethod:    "oidc",
					Timestamp:     time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC),
				},
			},
		},
		{
			name:  "multiple entries with mixed results",
			orgID: "org-test-2",
			entries: []Entry{
				{
					RequestID:     "req-010",
					User:          "user:bob",
					Relation:      "write",
					Object:        "document:spec",
					Allowed:       false,
					MatchedRule:   "data.atol.allow",
					EvalUs:        85,
					ZanzibarCalls: 2,
					AuthMethod:    "api_key",
					Timestamp:     time.Date(2026, 3, 21, 10, 1, 0, 0, time.UTC),
				},
				{
					RequestID:     "req-011",
					User:          "spiffe://atol.sh/svc/reconciler",
					Relation:      "delete",
					Object:        "project:old",
					Allowed:       true,
					MatchedRule:   "zanzibar.check",
					EvalUs:        31,
					ZanzibarCalls: 1,
					AuthMethod:    "spiffe",
					Timestamp:     time.Date(2026, 3, 21, 10, 2, 0, 0, time.UTC),
				},
			},
		},
		{
			name:    "empty entries is a no-op",
			orgID:   "org-test-3",
			entries: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset captured logs for each sub-test.
			mock.mu.Lock()
			mock.received = nil
			mock.mu.Unlock()

			sink := NewRPCSink(srv.URL, tt.orgID)

			err := sink.Send(tt.entries)
			if err != nil {
				t.Fatalf("Send() error: %v", err)
			}

			logs := mock.logs()

			if len(tt.entries) == 0 {
				if len(logs) != 0 {
					t.Errorf("expected 0 captured logs for empty send, got %d", len(logs))
				}
				return
			}

			if len(logs) != len(tt.entries) {
				t.Fatalf("captured %d logs, want %d", len(logs), len(tt.entries))
			}

			for i, entry := range tt.entries {
				got := logs[i]

				if got.OrgID != tt.orgID {
					t.Errorf("logs[%d].OrgID = %q, want %q", i, got.OrgID, tt.orgID)
				}
				if got.RequestID != entry.RequestID {
					t.Errorf("logs[%d].RequestID = %q, want %q", i, got.RequestID, entry.RequestID)
				}
				// RPCSink maps Entry.User -> DecisionLog.ActorIdentity
				if got.ActorIdentity != entry.User {
					t.Errorf("logs[%d].ActorIdentity = %q, want %q (from Entry.User)", i, got.ActorIdentity, entry.User)
				}
				if got.AuthMethod != entry.AuthMethod {
					t.Errorf("logs[%d].AuthMethod = %q, want %q", i, got.AuthMethod, entry.AuthMethod)
				}
				// RPCSink maps Entry.Relation -> DecisionLog.Action
				if got.Action != entry.Relation {
					t.Errorf("logs[%d].Action = %q, want %q (from Entry.Relation)", i, got.Action, entry.Relation)
				}
				// RPCSink maps Entry.Object -> DecisionLog.Resource
				if got.Resource != entry.Object {
					t.Errorf("logs[%d].Resource = %q, want %q (from Entry.Object)", i, got.Resource, entry.Object)
				}
				if got.Allowed != entry.Allowed {
					t.Errorf("logs[%d].Allowed = %v, want %v", i, got.Allowed, entry.Allowed)
				}
				if got.MatchedRule != entry.MatchedRule {
					t.Errorf("logs[%d].MatchedRule = %q, want %q", i, got.MatchedRule, entry.MatchedRule)
				}
				if got.EvalUs != entry.EvalUs {
					t.Errorf("logs[%d].EvalUs = %d, want %d", i, got.EvalUs, entry.EvalUs)
				}
				if got.ZanzibarCalls != entry.ZanzibarCalls {
					t.Errorf("logs[%d].ZanzibarCalls = %d, want %d", i, got.ZanzibarCalls, entry.ZanzibarCalls)
				}
				if !entry.Timestamp.IsZero() && !got.HasTimestamp {
					t.Errorf("logs[%d].Timestamp is nil, expected non-nil for non-zero input", i)
				}
			}
		})
	}
}

func TestRPCSink_Send_ServerError(t *testing.T) {
	t.Parallel()

	// Create a server that always returns an error.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sink := NewRPCSink(srv.URL, "org-err")

	err := sink.Send([]Entry{
		{
			RequestID: "req-err",
			User:      "user:alice",
			Relation:  "read",
			Object:    "doc:1",
			Allowed:   true,
		},
	})
	if err == nil {
		t.Fatal("expected error for server returning 500, got nil")
	}
}
