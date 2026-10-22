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
	persisted map[string]store.StoredModel
	saveErr   error
	entered   chan string
	blockYAML string
	release   <-chan struct{}
	listOnce  sync.Once
	listReady chan struct{}
	listBlock <-chan struct{}
}

func newModelCommitStore() *modelCommitStore {
	return &modelCommitStore{persisted: make(map[string]store.StoredModel)}
}

func (s *modelCommitStore) Save(ctx context.Context, tenantID, modelYAML, _ string) (int64, error) {
	if s.entered != nil {
		s.entered <- modelYAML
	}
	if modelYAML == s.blockYAML && s.release != nil {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.release:
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return 0, s.saveErr
	}
	revision := s.persisted[tenantID].Revision + 1
	s.persisted[tenantID] = store.StoredModel{YAML: modelYAML, Revision: revision}
	return revision, nil
}

func (s *modelCommitStore) Get(_ context.Context, tenantID string) (store.StoredModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persisted[tenantID], nil
}

func (s *modelCommitStore) ListAll(context.Context) (map[string]store.StoredModel, error) {
	s.mu.Lock()
	models := make(map[string]store.StoredModel, len(s.persisted))
	for tenantID, source := range s.persisted {
		models[tenantID] = source
	}
	s.mu.Unlock()
	if s.listReady != nil {
		s.listOnce.Do(func() { close(s.listReady) })
	}
	if s.listBlock != nil {
		<-s.listBlock
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
			if persisted.YAML != modelCommitAYAML {
				t.Fatalf("persisted model = %q, want model A", persisted.YAML)
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
	if active != modelCommitBYAML || persisted.YAML != active {
		t.Fatalf("active/persisted models diverged: active %q persisted %q", active, persisted.YAML)
	}
	if got := notifier.updateCount(); got != 2 {
		t.Fatalf("model notifications = %d, want 2", got)
	}
}

func TestActivateModelForTenantDropsStaleAndDuplicateRevisions(t *testing.T) {
	engine := New(store.NewMemoryStore(), nil, nil)
	ctx := context.Background()
	const tenantID = "tenant-a"

	if err := engine.ActivateModelForTenant(ctx, tenantID, []byte(modelCommitBYAML), 2); err != nil {
		t.Fatalf("activate revision 2: %v", err)
	}
	for _, revision := range []int64{2, 1} {
		if err := engine.ActivateModelForTenant(ctx, tenantID, []byte(modelCommitAYAML), revision); err != nil {
			t.Fatalf("activate revision %d: %v", revision, err)
		}
	}

	if got := string(engine.GetModelSourceYAML(ctx, tenantID)); got != modelCommitBYAML {
		t.Fatalf("active model = %q, want revision 2 model", got)
	}
	if got := engine.ModelRevisionForTenant(ctx, tenantID); got != 2 {
		t.Fatalf("active revision = %d, want 2", got)
	}
}

func TestModelSnapshotForTenantKeepsSourceAndRevisionAtomic(t *testing.T) {
	engine := New(store.NewMemoryStore(), nil, nil)
	ctx := context.Background()
	const tenantID = "tenant-a"
	if err := engine.ActivateModelForTenant(ctx, tenantID, []byte(modelCommitAYAML), 1); err != nil {
		t.Fatalf("activate initial model: %v", err)
	}

	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		defer close(done)
		for revision := int64(2); revision <= 1000; revision++ {
			source := modelCommitAYAML
			if revision%2 == 0 {
				source = modelCommitBYAML
			}
			if err := engine.ActivateModelForTenant(ctx, tenantID, []byte(source), revision); err != nil {
				errCh <- err
				return
			}
		}
	}()

	for {
		snapshot := engine.ModelSnapshotForTenant(ctx, tenantID)
		want := modelCommitAYAML
		if snapshot.Revision%2 == 0 {
			want = modelCommitBYAML
		}
		if string(snapshot.YAML) != want {
			t.Fatalf("snapshot revision %d has source %q, want %q", snapshot.Revision, snapshot.YAML, want)
		}
		select {
		case <-done:
			select {
			case err := <-errCh:
				t.Fatalf("activate model: %v", err)
			default:
			}
			mutated := engine.ModelSnapshotForTenant(ctx, tenantID)
			mutated.YAML[0] = 'x'
			if got := engine.ModelSnapshotForTenant(ctx, tenantID); len(got.YAML) == 0 || got.YAML[0] == 'x' {
				t.Fatal("snapshot YAML aliases the cached model source")
			}
			return
		default:
		}
	}
}

func TestRefreshModelForTenantConvergesAnotherEngine(t *testing.T) {
	modelStore := newModelCommitStore()
	writer := New(store.NewMemoryStore(), modelStore, nil)
	reader := New(store.NewMemoryStore(), modelStore, nil)
	ctx := context.Background()
	const tenantID = "tenant-a"

	revision, err := writer.SaveModelForTenant(ctx, tenantID, []byte(modelCommitBYAML), "writer")
	if err != nil {
		t.Fatalf("save model: %v", err)
	}
	if err := writer.ActivateModelForTenant(ctx, tenantID, []byte(modelCommitBYAML), revision); err != nil {
		t.Fatalf("activate writer model: %v", err)
	}

	snapshot, err := reader.RefreshModelForTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("refresh reader model: %v", err)
	}
	if snapshot.Revision != revision || string(snapshot.YAML) != modelCommitBYAML {
		t.Fatalf("reader snapshot = (%d, %q), want (%d, model B)", snapshot.Revision, snapshot.YAML, revision)
	}
}

func TestActivateModelDropsStaleAndDuplicateRevisions(t *testing.T) {
	engine := New(store.NewMemoryStore(), nil, nil)

	if err := engine.ActivateModel([]byte(modelCommitBYAML), 2); err != nil {
		t.Fatalf("activate revision 2: %v", err)
	}
	for _, revision := range []int64{2, 1} {
		if err := engine.ActivateModel([]byte(modelCommitAYAML), revision); err != nil {
			t.Fatalf("activate revision %d: %v", revision, err)
		}
	}

	if _, ok := engine.GetModel().Types["clinic"]; !ok {
		t.Fatal("active model regressed from revision 2")
	}
	if got := engine.ModelRevision(); got != 2 {
		t.Fatalf("active revision = %d, want 2", got)
	}
}

func TestLoadPersistedModelsDoesNotRegressConcurrentActivation(t *testing.T) {
	modelStore := newModelCommitStore()
	modelStore.persisted["tenant-a"] = store.StoredModel{YAML: modelCommitAYAML, Revision: 1}
	modelStore.listReady = make(chan struct{})
	release := make(chan struct{})
	modelStore.listBlock = release
	engine := New(store.NewMemoryStore(), modelStore, nil)

	loaded := make(chan error, 1)
	go func() { loaded <- engine.LoadPersistedModels(context.Background()) }()
	<-modelStore.listReady
	if err := engine.ActivateModelForTenant(
		context.Background(), "tenant-a", []byte(modelCommitBYAML), 2,
	); err != nil {
		t.Fatalf("activate concurrent revision: %v", err)
	}
	close(release)
	if err := <-loaded; err != nil {
		t.Fatalf("LoadPersistedModels: %v", err)
	}

	snapshot := engine.ModelSnapshotForTenant(context.Background(), "tenant-a")
	if snapshot.Revision != 2 || string(snapshot.YAML) != modelCommitBYAML {
		t.Fatalf("snapshot = (%d, %q), want concurrent revision 2", snapshot.Revision, snapshot.YAML)
	}
}

func TestLoadPersistedModelsRejectsNonpositiveRevision(t *testing.T) {
	modelStore := newModelCommitStore()
	modelStore.persisted["tenant-a"] = store.StoredModel{YAML: modelCommitAYAML, Revision: 0}
	engine := New(store.NewMemoryStore(), modelStore, nil)

	if err := engine.LoadPersistedModels(context.Background()); err == nil {
		t.Fatal("LoadPersistedModels accepted revision zero")
	}
	if snapshot := engine.ModelSnapshotForTenant(context.Background(), "tenant-a"); snapshot.Revision != 0 || len(snapshot.YAML) != 0 {
		t.Fatalf("invalid persisted model became active: %+v", snapshot)
	}
}
