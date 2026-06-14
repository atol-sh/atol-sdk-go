package sync_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	"atol.sh/sdk-go/gen/go/atol/api/v1/apiv1connect"
	policyengine "atol.sh/sdk-go/policy/engine"
	atolsync "atol.sh/sdk-go/sync"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"

	"connectrpc.com/connect"
)

var testModel = []byte(`
types:
  user: {}
  document:
    relations:
      owner:
        types: [user]
      editor:
        types: [user]
      viewer:
        union: [owner, editor]
`)

// TestNewClient verifies that NewClient creates a valid client with all fields.
func TestNewClient(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)
	logger := zap.NewNop()

	c := atolsync.NewClient("http://localhost:9080", "org-1", "tok-1", nil, z, p, logger)
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.ContinuationToken() != "tok-1" {
		t.Errorf("ContinuationToken() = %q, want %q", c.ContinuationToken(), "tok-1")
	}
}

// TestNewClient_NilHTTPClient verifies that nil httpClient defaults safely.
func TestNewClient_NilHTTPClient(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	c := atolsync.NewClient("http://localhost:9080", "org-1", "tok-1", nil, z, p, zap.NewNop())
	if c == nil {
		t.Fatal("NewClient with nil httpClient returned nil")
	}
}

// TestRun_CancelledContext verifies that Run exits promptly on context cancellation.
func TestRun_CancelledContext(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	// Use a server that always returns an error so Run enters the retry loop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := atolsync.NewClient(srv.URL, "org-1", "tok-1", srv.Client(), z, p, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	// Give it a moment to attempt connection, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Run exited cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after context cancellation")
	}
}

// TestRun_PreCancelledContext verifies that Run exits immediately
// when the context is already cancelled.
func TestRun_PreCancelledContext(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	c := atolsync.NewClient("http://localhost:0", "org-1", "tok-1", nil, z, p, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before Run.

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Run exited immediately.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit with pre-cancelled context")
	}
}

// TestStream_AppliesTupleWriteAndDelete verifies that tuple mutations from
// the stream are applied to the Zanzibar engine. This test spins up a
// real Connect server that pushes mutations.
func TestStream_AppliesTupleWriteAndDelete(t *testing.T) {
	t.Helper()

	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	if err := z.LoadModel(testModel); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	// Create a mock DPAgentService that streams two mutations: write then delete.
	handler := &mockDPAgentHandler{
		mutations: []*apiv1.StreamMutationsResponse{
			{
				Mutation: &apiv1.StreamMutationsResponse_TupleWrite{
					TupleWrite: &apiv1.TupleWrite{
						Tuple: &apiv1.Tuple{
							User:     "user:alice",
							Relation: "editor",
							Object:   "document:doc-1",
						},
					},
				},
				ContinuationToken: "tok-2",
			},
			{
				Mutation: &apiv1.StreamMutationsResponse_TupleDelete{
					TupleDelete: &apiv1.TupleDelete{
						Tuple: &apiv1.Tuple{
							User:     "user:alice",
							Relation: "editor",
							Object:   "document:doc-1",
						},
					},
				},
				ContinuationToken: "tok-3",
			},
		},
	}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := atolsync.NewClient(srv.URL, "org-1", "tok-1", srv.Client(), z, p, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	// Wait for mutations to be applied.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for continuation token to advance")
		default:
		}
		if c.ContinuationToken() == "tok-3" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	// After write + delete, the tuple should be gone.
	tuples, err := s.Read(context.Background(), model.TupleFilter{
		ObjectType: "document",
		ObjectID:   "doc-1",
		Relation:   "editor",
		UserType:   "user",
		UserID:     "alice",
	})
	if err != nil {
		t.Fatalf("Read tuples: %v", err)
	}
	if len(tuples) != 0 {
		t.Errorf("expected 0 tuples after write+delete, got %d", len(tuples))
	}

	if c.ContinuationToken() != "tok-3" {
		t.Errorf("ContinuationToken() = %q, want %q", c.ContinuationToken(), "tok-3")
	}
}

// TestStream_AppliesModelUpdate verifies that a model update mutation
// replaces the Zanzibar model.
func TestStream_AppliesModelUpdate(t *testing.T) {
	t.Helper()

	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	if err := z.LoadModel(testModel); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	newModel := `
types:
  user: {}
  project:
    relations:
      admin:
        types: [user]
`

	handler := &mockDPAgentHandler{
		mutations: []*apiv1.StreamMutationsResponse{
			{
				Mutation: &apiv1.StreamMutationsResponse_ModelUpdate{
					ModelUpdate: &apiv1.ModelUpdate{
						AuthorizationModel: newModel,
					},
				},
				ContinuationToken: "tok-model",
			},
		},
	}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := atolsync.NewClient(srv.URL, "org-1", "tok-1", srv.Client(), z, p, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for model update")
		default:
		}
		if c.ContinuationToken() == "tok-model" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	// Verify the new model has "project" type.
	m := z.GetModel()
	if m == nil {
		t.Fatal("model is nil after update")
	}
	if _, ok := m.Types["project"]; !ok {
		t.Error("model does not contain 'project' type after update")
	}
}

// TestStream_NilMutationFields verifies that nil/empty mutation fields
// are handled gracefully without panics.
func TestStream_NilMutationFields(t *testing.T) {
	t.Helper()

	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	handler := &mockDPAgentHandler{
		mutations: []*apiv1.StreamMutationsResponse{
			{
				Mutation:          &apiv1.StreamMutationsResponse_TupleWrite{TupleWrite: nil},
				ContinuationToken: "tok-nil-1",
			},
			{
				Mutation:          &apiv1.StreamMutationsResponse_TupleWrite{TupleWrite: &apiv1.TupleWrite{Tuple: nil}},
				ContinuationToken: "tok-nil-2",
			},
			{
				Mutation:          &apiv1.StreamMutationsResponse_TupleDelete{TupleDelete: nil},
				ContinuationToken: "tok-nil-3",
			},
			{
				Mutation:          &apiv1.StreamMutationsResponse_ModelUpdate{ModelUpdate: nil},
				ContinuationToken: "tok-nil-4",
			},
			{
				Mutation:          &apiv1.StreamMutationsResponse_ModelUpdate{ModelUpdate: &apiv1.ModelUpdate{AuthorizationModel: ""}},
				ContinuationToken: "tok-nil-5",
			},
			{
				Mutation:          &apiv1.StreamMutationsResponse_PolicyBundleUpdate{PolicyBundleUpdate: nil},
				ContinuationToken: "tok-nil-6",
			},
			{
				Mutation:          &apiv1.StreamMutationsResponse_PolicyDataUpdate{PolicyDataUpdate: nil},
				ContinuationToken: "tok-nil-7",
			},
		},
	}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := atolsync.NewClient(srv.URL, "org-1", "tok-0", srv.Client(), z, p, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for nil mutations to be processed")
		default:
		}
		if c.ContinuationToken() == "tok-nil-7" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done
}

// TestRun_RebootstrapOnRefusedTokenAtOpen verifies that a
// CodeFailedPrecondition at stream open triggers the rebootstrap callback
// and replaces the stored continuation token with the fresh one.
func TestRun_RebootstrapOnRefusedTokenAtOpen(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	handler := &refusingDPAgentHandler{
		refuseToken: "stale-tok",
		mutations: []*apiv1.StreamMutationsResponse{
			{ContinuationToken: "tok-after-fresh"},
		},
	}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var rebootstrapCalls atomic.Int32
	rebootstrap := func(_ context.Context) (string, error) {
		rebootstrapCalls.Add(1)
		return "fresh-tok", nil
	}

	c := atolsync.NewClient(srv.URL, "org-1", "stale-tok", srv.Client(), z, p, zap.NewNop(),
		atolsync.WithRebootstrap(rebootstrap))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	deadline := time.After(10 * time.Second)
	for c.ContinuationToken() != "tok-after-fresh" {
		select {
		case <-deadline:
			t.Fatalf("timed out: ContinuationToken() = %q, want %q (rebootstrap calls: %d)",
				c.ContinuationToken(), "tok-after-fresh", rebootstrapCalls.Load())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if got := rebootstrapCalls.Load(); got < 1 {
		t.Errorf("rebootstrap calls = %d, want >= 1", got)
	}
	if !handler.sawToken("fresh-tok") {
		t.Errorf("server never saw fresh token %q, got tokens %v", "fresh-tok", handler.tokens())
	}
}

// TestRun_RebootstrapOnRefusedTokenMidStream verifies that a
// CodeFailedPrecondition surfaced via stream.Err() after some mutations
// also triggers rebootstrap and token replacement.
func TestRun_RebootstrapOnRefusedTokenMidStream(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	handler := &refusingDPAgentHandler{
		refuseToken: "tok-mid", // refuse only after the client advanced to the mid-stream token
		preRefusal: []*apiv1.StreamMutationsResponse{
			{ContinuationToken: "tok-mid"},
		},
		refuseMidStream: true,
		mutations: []*apiv1.StreamMutationsResponse{
			{ContinuationToken: "tok-after-fresh-2"},
		},
	}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var rebootstrapCalls atomic.Int32
	rebootstrap := func(_ context.Context) (string, error) {
		rebootstrapCalls.Add(1)
		return "fresh-tok-2", nil
	}

	c := atolsync.NewClient(srv.URL, "org-1", "tok-start", srv.Client(), z, p, zap.NewNop(),
		atolsync.WithRebootstrap(rebootstrap))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	deadline := time.After(10 * time.Second)
	for c.ContinuationToken() != "tok-after-fresh-2" {
		select {
		case <-deadline:
			t.Fatalf("timed out: ContinuationToken() = %q, want %q (rebootstrap calls: %d)",
				c.ContinuationToken(), "tok-after-fresh-2", rebootstrapCalls.Load())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if got := rebootstrapCalls.Load(); got < 1 {
		t.Errorf("rebootstrap calls = %d, want >= 1", got)
	}
	if !handler.sawToken("fresh-tok-2") {
		t.Errorf("server never saw fresh token %q, got tokens %v", "fresh-tok-2", handler.tokens())
	}
}

// TestRun_RefusedTokenWithoutRebootstrapStops verifies that a refused token
// with no rebootstrap callback stops the loop instead of retrying the same
// refused token forever.
func TestRun_RefusedTokenWithoutRebootstrapStops(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	handler := &refusingDPAgentHandler{refuseToken: "stale-tok"}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := atolsync.NewClient(srv.URL, "org-1", "stale-tok", srv.Client(), z, p, zap.NewNop())

	done := make(chan struct{})
	go func() {
		c.Run(context.Background())
		close(done)
	}()

	select {
	case <-done:
		// Run stopped as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after refused token with no rebootstrap callback")
	}
}

// TestRun_NormalReconnectKeepsLastToken verifies that an ordinary stream
// error (not FailedPrecondition) reconnects with the last per-mutation
// token received, without invoking rebootstrap.
func TestRun_NormalReconnectKeepsLastToken(t *testing.T) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)

	handler := &refusingDPAgentHandler{
		preRefusal: []*apiv1.StreamMutationsResponse{
			{ContinuationToken: "tok-advanced"},
		},
		failUnavailableOnce: true,
	}

	mux := http.NewServeMux()
	path, h := apiv1connect.NewDPAgentServiceHandler(handler)
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rebootstrap := func(_ context.Context) (string, error) {
		t.Error("rebootstrap called on a normal stream error, want none")
		return "", nil
	}

	c := atolsync.NewClient(srv.URL, "org-1", "tok-start", srv.Client(), z, p, zap.NewNop(),
		atolsync.WithRebootstrap(rebootstrap))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	// Wait until the server has seen a reconnect carrying the advanced token.
	deadline := time.After(10 * time.Second)
	for !handler.sawToken("tok-advanced") {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for reconnect with last token; server saw %v", handler.tokens())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done

	if c.ContinuationToken() != "tok-advanced" {
		t.Errorf("ContinuationToken() = %q, want %q", c.ContinuationToken(), "tok-advanced")
	}
}

// mockDPAgentHandler implements the DPAgentService for testing.
type mockDPAgentHandler struct {
	apiv1connect.UnimplementedDPAgentServiceHandler
	mutations []*apiv1.StreamMutationsResponse
}

func (h *mockDPAgentHandler) StreamMutations(_ context.Context, _ *connect.Request[apiv1.StreamMutationsRequest], stream *connect.ServerStream[apiv1.StreamMutationsResponse]) error {
	for _, m := range h.mutations {
		if err := stream.Send(m); err != nil {
			return err
		}
	}
	return nil
}

// refusingDPAgentHandler implements DPAgentService with configurable
// continuation-token refusal for rebootstrap tests. It records every
// continuation token offered by the client.
type refusingDPAgentHandler struct {
	apiv1connect.UnimplementedDPAgentServiceHandler

	// refuseToken, when non-empty, is refused with CodeFailedPrecondition.
	refuseToken string
	// refuseMidStream sends preRefusal mutations first and refuses at
	// stream end instead of at open.
	refuseMidStream bool
	// preRefusal mutations are streamed before any refusal check (and on
	// every connection that is not refused).
	preRefusal []*apiv1.StreamMutationsResponse
	// failUnavailableOnce makes the first connection end with
	// CodeUnavailable after streaming preRefusal mutations.
	failUnavailableOnce bool
	// mutations are streamed on accepted connections.
	mutations []*apiv1.StreamMutationsResponse

	mu        gosync.Mutex
	seen      []string
	failedYet bool
}

func (h *refusingDPAgentHandler) StreamMutations(_ context.Context, req *connect.Request[apiv1.StreamMutationsRequest], stream *connect.ServerStream[apiv1.StreamMutationsResponse]) error {
	token := req.Msg.GetContinuationToken()

	h.mu.Lock()
	h.seen = append(h.seen, token)
	failFirst := h.failUnavailableOnce && !h.failedYet
	if failFirst {
		h.failedYet = true
	}
	h.mu.Unlock()

	refused := h.refuseToken != "" && token == h.refuseToken
	if refused && !h.refuseMidStream {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("continuation token too old: re-bootstrap required"))
	}

	for _, m := range h.preRefusal {
		if err := stream.Send(m); err != nil {
			return err
		}
	}

	if h.refuseMidStream {
		// The mid-stream refusal triggers on the *next* connection, after
		// the client advanced to the refuse token via preRefusal.
		if refused {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("continuation token too old: re-bootstrap required"))
		}
		if token != "" && token != h.refuseToken && h.sawToken(h.refuseToken) {
			// Accepted post-rebootstrap connection: stream the fresh mutations.
			for _, m := range h.mutations {
				if err := stream.Send(m); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if failFirst {
		return connect.NewError(connect.CodeUnavailable, errors.New("transient outage"))
	}

	for _, m := range h.mutations {
		if err := stream.Send(m); err != nil {
			return err
		}
	}
	return nil
}

func (h *refusingDPAgentHandler) sawToken(token string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.seen {
		if s == token {
			return true
		}
	}
	return false
}

func (h *refusingDPAgentHandler) tokens() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.seen))
	copy(out, h.seen)
	return out
}
