package store

import "context"

// ModelStore persists per-tenant Zanzibar authorization models.
type ModelStore interface {
	Save(ctx context.Context, tenantID, modelYAML, createdBy string) error
	Get(ctx context.Context, tenantID string) (string, error)
	ListAll(ctx context.Context) (map[string]string, error) // tenantID -> YAML
}
