package sdk

import (
	"context"
	"errors"

	atolsync "atol.sh/sdk-go/sync"
	zstore "atol.sh/sdk-go/zanzibar/store"
)

var (
	// ErrTenantServingRestricted reports a durable erasure restriction.
	ErrTenantServingRestricted = atolsync.ErrTenantServingRestricted
	// ErrTenantServingLeaseUnavailable reports that no current authoritative
	// serving lease permits authorization decisions.
	ErrTenantServingLeaseUnavailable = atolsync.ErrTenantServingLeaseUnavailable
	// ErrTenantServingScopeMismatch reports cross-tenant use of a tenant gate.
	ErrTenantServingScopeMismatch = atolsync.ErrTenantServingScopeMismatch
)

// TenantServingRestrictedError carries the durable restriction authority.
type TenantServingRestrictedError = atolsync.TenantServingRestrictedError

func (a *Atol) requireServingActive(ctx context.Context) error {
	if !a.servingGateRequired {
		return nil
	}
	if a.servingGate == nil {
		return ErrTenantServingLeaseUnavailable
	}
	if err := a.servingGate.RequireActive(zstore.TenantFromContext(ctx)); err != nil {
		if errors.Is(err, ErrTenantServingRestricted) || errors.Is(err, ErrTenantServingScopeMismatch) {
			return err
		}
		return ErrTenantServingLeaseUnavailable
	}
	return nil
}
