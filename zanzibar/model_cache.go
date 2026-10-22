package zanzibar

import (
	"context"
	"fmt"
)

// ModelSnapshot is an immutable view of one active authorization model.
// YAML is copied when the snapshot is created so callers cannot mutate the
// engine's cached source or observe a source/revision pair from two updates.
type ModelSnapshot struct {
	YAML     []byte
	Revision int64
}

// GetModelSourceYAML returns the original YAML source for the tenant's model.
// Returns nil if no source was stored (e.g., model was set via SetModel).
func (e *Engine) GetModelSourceYAML(ctx context.Context, tenantID string) []byte {
	return e.ModelSnapshotForTenant(ctx, tenantID).YAML
}

// ModelSnapshotForTenant returns the active tenant model source and revision
// from one cache entry. The returned YAML is a defensive copy.
func (e *Engine) ModelSnapshotForTenant(ctx context.Context, tenantID string) ModelSnapshot {
	tm := e.resolveModel(ctx, tenantID)
	if tm == nil {
		return ModelSnapshot{}
	}
	return ModelSnapshot{
		YAML:     append([]byte(nil), tm.sourceYAML...),
		Revision: tm.revision,
	}
}

// RefreshModelForTenant reads the tenant's committed model from the
// authoritative store, applies it through the monotonic activation fence, and
// returns one immutable active snapshot. When no tenant model is persisted,
// the current default snapshot is returned.
func (e *Engine) RefreshModelForTenant(ctx context.Context, tenantID string) (ModelSnapshot, error) {
	if tenantID == "" {
		return ModelSnapshot{}, fmt.Errorf("tenant id is required")
	}
	if e.modelStore == nil {
		return ModelSnapshot{}, fmt.Errorf("refresh model: model store is not configured")
	}
	stored, err := e.modelStore.Get(ctx, tenantID)
	if err != nil {
		return ModelSnapshot{}, fmt.Errorf("refresh model: %w", err)
	}
	if stored.YAML == "" && stored.Revision == 0 {
		return e.ModelSnapshotForTenant(ctx, tenantID), nil
	}
	if stored.YAML == "" || stored.Revision <= 0 {
		return ModelSnapshot{}, fmt.Errorf("refresh model: invalid stored model revision %d", stored.Revision)
	}
	if err := e.ActivateModelForTenant(ctx, tenantID, []byte(stored.YAML), stored.Revision); err != nil {
		return ModelSnapshot{}, fmt.Errorf("refresh model: %w", err)
	}
	return e.ModelSnapshotForTenant(ctx, tenantID), nil
}

// ModelRevision returns the active default model revision.
func (e *Engine) ModelRevision() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.defaultModel == nil {
		return 0
	}
	return e.defaultModel.revision
}

// ModelRevisionForTenant returns the active tenant model revision, or the
// default model revision when the tenant has no specific model.
func (e *Engine) ModelRevisionForTenant(ctx context.Context, tenantID string) int64 {
	return e.ModelSnapshotForTenant(ctx, tenantID).Revision
}

// LoadPersistedModels loads all persisted per-tenant models from the DB into
// the monotonic cache. Called at startup after the default model is loaded.
func (e *Engine) LoadPersistedModels(ctx context.Context) error {
	if e.modelStore == nil {
		return nil
	}

	models, err := e.modelStore.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list persisted models: %w", err)
	}
	for tenantID, stored := range models {
		if stored.YAML == "" || stored.Revision <= 0 {
			return fmt.Errorf("load persisted model for tenant %s: invalid revision %d", tenantID, stored.Revision)
		}
		if err := e.ActivateModelForTenant(ctx, tenantID, []byte(stored.YAML), stored.Revision); err != nil {
			return fmt.Errorf("load persisted model for tenant %s: %w", tenantID, err)
		}
	}
	return nil
}
