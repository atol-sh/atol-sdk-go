// Package sync provides change notification interfaces for the Zanzibar engine.
// The control plane implements these to push mutations to connected SDK instances.
package sync

import (
	"context"

	"atol.sh/sdk-go/zanzibar/model"
)

// ChangeNotifier receives notifications when tuples or models change.
// Implementations push these changes to connected SDK instances.
//
// The context carries the tenant scope of the originating write (see
// store.TenantFromContext); multi-tenant implementations use it to route
// the change to the correct tenant's subscribers.
type ChangeNotifier interface {
	OnTupleWrite(ctx context.Context, t model.Tuple)
	OnTupleDelete(ctx context.Context, t model.Tuple)
	OnModelUpdate(ctx context.Context, tenantID string, m *model.Model)
}

// NoopNotifier is a ChangeNotifier that does nothing.
type NoopNotifier struct{}

func (NoopNotifier) OnTupleWrite(_ context.Context, _ model.Tuple)             {}
func (NoopNotifier) OnTupleDelete(_ context.Context, _ model.Tuple)            {}
func (NoopNotifier) OnModelUpdate(_ context.Context, _ string, _ *model.Model) {}
