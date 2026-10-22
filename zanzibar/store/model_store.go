package store

import "context"

// StoredModel is a persisted authorization model and its monotonic revision.
type StoredModel struct {
	YAML     string
	Revision int64
}

// ModelStore persists per-tenant Zanzibar authorization models.
type ModelStore interface {
	Save(ctx context.Context, tenantID, modelYAML, createdBy string) (revision int64, err error)
	Get(ctx context.Context, tenantID string) (StoredModel, error)
	ListAll(ctx context.Context) (map[string]StoredModel, error)
}
