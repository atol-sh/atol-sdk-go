package zanzibar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

const modelCommitAYAML = `version: "1.0"
types:
  user: {}
  warehouse: {}
`

const modelCommitBYAML = `version: "1.0"
types:
  user: {}
  clinic: {}
`

var errModelCommit = errors.New("model commit failed")

type modelCommitStore struct {
	mu        sync.Mutex
	persisted map[string]string
	saveErr   error
	entered   chan string
	blockYAML string
	release   <-chan struct{}
}

func newModelCommitStore() *modelCommitStore {
	return &modelCommitStore{persisted: make(map[string]string)}
}

func (s *modelCommitStore) Save(ctx context.Context, tenantID, modelYAML, _ string) error {
	if s.entered != nil {
		s.entered <- modelYAML
	}
	if modelYAML == s.blockYAML && s.release != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.release:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.persisted[tenantID] = modelYAML
	return nil
}

func (s *modelCommitStore) Get(_ context.Context, tenantID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persisted[tenantID], nil
}

func (s *modelCommitStore) ListAll(context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	models := make(map[string]string, len(s.persisted))
	for tenantID, source := range s.persisted {
		models[tenantID] = source
	}
	return models, nil
}

func (s *modelCommitStore) failWith(err error) {
	s.mu.Lock()
	s.saveErr = err
	s.mu.Unlock()
}

type modelCommitNotifier struct {
	mu      sync.Mutex
	updates int
}

func (*modelCommitNotifier) OnTupleWrite(context.Context, model.Tuple)  {}
func (*modelCommitNotifier) OnTupleDelete(context.Context, model.Tuple) {}
func (n *modelCommitNotifier) OnModelUpdate(context.Context, string, *model.Model) {
	n.mu.Lock()
	n.updates++
	n.mu.Unlock()
}

func (n *modelCommitNotifier) updateCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.updates
}

func TestLoadModelForTenantFailedCommitLeavesLastCommittedModel(t *testing.T) {
	tests := []struct {
		name       string
		commitErr  error
		cancelCall bool
	}{
		{name: "store failure", commitErr: errModelCommit},
		{name: "canceled request", commitErr: context.Canceled, cancelCall: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modelStore := newModelCommitStore()
			notifier := &modelCommitNotifier{}
			engine := New(store.NewMemoryStore(), modelStore, notifier)
			const tenantID = "tenant-a"

			if err := engine.LoadModelForTenant(
				context.Background(), tenantID, []byte(modelCommitAYAML),
			); err != nil {
				t.Fatalf("seed model A: %v", err)
			}

			ctx := context.Background()
			if tt.cancelCall {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			} else {
				modelStore.failWith(tt.commitErr)
			}
			err := engine.LoadModelForTenant(ctx, tenantID, []byte(modelCommitBYAML))
			if !errors.Is(err, tt.commitErr) {
				t.Fatalf("LoadModelForTenant() error = %v, want %v", err, tt.commitErr)
			}

			if got := string(engine.GetModelSourceYAML(context.Background(), tenantID)); got != modelCommitAYAML {
				t.Fatalf("active model = %q, want committed model A", got)
			}
			persisted, getErr := modelStore.Get(context.Background(), tenantID)
			if getErr != nil {
				t.Fatalf("read persisted model: %v", getErr)
			}
			if persisted != modelCommitAYAML {
				t.Fatalf("persisted model = %q, want model A", persisted)
			}
			if got := notifier.updateCount(); got != 1 {
				t.Fatalf("model notifications = %d, want 1", got)
			}
		})
	}
}

func TestLoadModelForTenantSerializesCommitActivationAndNotification(t *testing.T) {
	releaseA := make(chan struct{})
	modelStore := newModelCommitStore()
	modelStore.entered = make(chan string, 2)
	modelStore.blockYAML = modelCommitAYAML
	modelStore.release = releaseA
	notifier := &modelCommitNotifier{}
	engine := New(store.NewMemoryStore(), modelStore, notifier)
	const tenantID = "tenant-a"

	errA := make(chan error, 1)
	go func() {
		errA <- engine.LoadModelForTenant(
			context.Background(), tenantID, []byte(modelCommitAYAML),
		)
	}()
	if entered := <-modelStore.entered; entered != modelCommitAYAML {
		t.Fatalf("first persistence = %q, want model A", entered)
	}

	startedB := make(chan struct{})
	errB := make(chan error, 1)
	go func() {
		close(startedB)
		errB <- engine.LoadModelForTenant(
			context.Background(), tenantID, []byte(modelCommitBYAML),
		)
	}()
	<-startedB

	var earlyPersistence string
	select {
	case earlyPersistence = <-modelStore.entered:
	case <-time.After(time.Second):
	}
	close(releaseA)
	if err := <-errA; err != nil {
		t.Fatalf("commit model A: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("commit model B: %v", err)
	}
	if earlyPersistence != "" {
		t.Fatalf("model B entered persistence before model A committed: %q", earlyPersistence)
	}

	persisted, err := modelStore.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("read persisted model: %v", err)
	}
	active := string(engine.GetModelSourceYAML(context.Background(), tenantID))
	if active != modelCommitBYAML || persisted != active {
		t.Fatalf("active/persisted models diverged: active %q persisted %q", active, persisted)
	}
	if got := notifier.updateCount(); got != 2 {
		t.Fatalf("model notifications = %d, want 2", got)
	}
}
