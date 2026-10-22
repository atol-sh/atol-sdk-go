package zanzibar

import (
	"context"
	"fmt"

	"atol.sh/sdk-go/zanzibar/store"
)

// TenantServingGate denies authorization decisions unless the tenant has a
// current authoritative active lease. Implementations must fail closed.
type TenantServingGate interface {
	RequireActive(tenantID string) error
}

// SetTenantServingGate installs the central authorization serving gate. The
// SDK wires this before exposing the engine to callers.
func (e *Engine) SetTenantServingGate(gate TenantServingGate) {
	e.mu.Lock()
	e.servingGate = gate
	e.mu.Unlock()
}

func (e *Engine) requireTenantServing(ctx context.Context) error {
	e.mu.RLock()
	gate := e.servingGate
	e.mu.RUnlock()
	if gate == nil {
		return nil
	}
	if err := gate.RequireActive(store.TenantFromContext(ctx)); err != nil {
		return fmt.Errorf("tenant authorization serving is unavailable: %w", err)
	}
	return nil
}
