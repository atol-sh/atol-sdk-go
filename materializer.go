package sdk

import (
	"context"
	"fmt"
	"sync"

	"atol.sh/sdk-go/zanzibar/model"
	"atol.sh/sdk-go/zanzibar/store"
)

// MaterializerFunc produces tuples from the app's own data source.
// Called at bootstrap and on-demand via Materialize/MaterializeAll.
// The returned tuples replace all previous tuples for this materializer.
type MaterializerFunc func(ctx context.Context) ([]model.Tuple, error)

// Materializer holds a registered materializer callback and its metadata.
type Materializer struct {
	Name string
	Fn   MaterializerFunc
}

// materializerRegistry manages registered materializers for the SDK.
type materializerRegistry struct {
	mu            sync.RWMutex
	materializers map[string]*Materializer
	store         *store.MemoryStore
}

func newMaterializerRegistry(s *store.MemoryStore) *materializerRegistry {
	return &materializerRegistry{
		materializers: make(map[string]*Materializer),
		store:         s,
	}
}

// register adds a materializer to the registry.
func (r *materializerRegistry) register(name string, fn MaterializerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.materializers[name] = &Materializer{Name: name, Fn: fn}
}

// materialize runs a single materializer by name and writes results to the store.
func (r *materializerRegistry) materialize(ctx context.Context, name string) error {
	r.mu.RLock()
	m, ok := r.materializers[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("materializer %q not registered", name)
	}

	tuples, err := m.Fn(ctx)
	if err != nil {
		return fmt.Errorf("materializer %q: %w", name, err)
	}

	r.store.WriteMaterialized(name, tuples)
	return nil
}

// materializeAll runs all registered materializers. Returns the first error
// encountered but continues running remaining materializers.
func (r *materializerRegistry) materializeAll(ctx context.Context) error {
	r.mu.RLock()
	names := make([]string, 0, len(r.materializers))
	for name := range r.materializers {
		names = append(names, name)
	}
	r.mu.RUnlock()

	var firstErr error
	for _, name := range names {
		if err := r.materialize(ctx, name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
