package sync

import (
	"errors"
	"fmt"
	gosync "sync"
	"time"

	"github.com/oklog/ulid/v2"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
)

const maxServingLease = 30 * time.Second

var (
	// ErrTenantServingRestricted reports a durable tenant erasure restriction.
	ErrTenantServingRestricted = errors.New("tenant serving is restricted")
	// ErrTenantServingLeaseUnavailable reports that no current authoritative
	// serving lease permits authorization decisions.
	ErrTenantServingLeaseUnavailable = errors.New("tenant serving lease is unavailable")
	// ErrTenantServingScopeMismatch reports an update or decision for another tenant.
	ErrTenantServingScopeMismatch = errors.New("tenant serving scope mismatch")
)

// TenantServingRestriction identifies the durable authority that stopped a tenant.
type TenantServingRestriction struct {
	Epoch                  int64
	RequestID              string
	Reason                 string
	AuthorityEventID       string
	AuthorityAppendOrdinal int64
}

// TenantServingRestrictedError carries the restriction authority while
// unwrapping to ErrTenantServingRestricted.
type TenantServingRestrictedError struct {
	Restriction TenantServingRestriction
}

func (e *TenantServingRestrictedError) Error() string {
	return fmt.Sprintf("tenant serving is restricted by request %s", e.Restriction.RequestID)
}

func (e *TenantServingRestrictedError) Unwrap() error { return ErrTenantServingRestricted }

// TenantServingGate is the per-SDK-instance, fail-closed decision gate. A
// restriction is sticky for the process lifetime; active lease frames cannot
// clear it.
type TenantServingGate struct {
	mu gosync.RWMutex

	tenantID       string
	leaseExpiresAt time.Time
	restriction    *TenantServingRestriction
	now            func() time.Time
}

// NewTenantServingGate creates a fail-closed unbound gate. BindTenant must
// receive the authenticated canonical tenant ID before live frames are accepted.
func NewTenantServingGate() *TenantServingGate {
	return &TenantServingGate{
		now: time.Now,
	}
}

// BindTenant records the canonical tenant returned by authenticated bootstrap.
// It is write-once except for idempotent rebinding to the same ID.
func (g *TenantServingGate) BindTenant(tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("bind tenant: tenant ID is empty")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tenantID != "" && g.tenantID != tenantID {
		return fmt.Errorf("bind tenant %q: %w", tenantID, ErrTenantServingScopeMismatch)
	}
	g.tenantID = tenantID
	return nil
}

// Renew accepts a challenge-bound active lease for the bound tenant.
func (g *TenantServingGate) Renew(tenantID, expectedChallenge string, update *apiv1.TenantServingStateUpdate) error {
	if update == nil || update.GetState() != apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE {
		return fmt.Errorf("renew tenant serving lease: active update required")
	}
	if update.GetEpoch() != 0 || update.GetRestrictionRequestId() != "" ||
		update.GetRestrictionReason() != "" || update.GetAuthorityEventId() != "" ||
		update.GetAuthorityAppendOrdinal() != 0 {
		return fmt.Errorf("renew tenant serving lease: active update contains restriction authority")
	}
	if expectedChallenge == "" || update.GetServingChallenge() != expectedChallenge {
		return fmt.Errorf("renew tenant serving lease: challenge mismatch")
	}
	if update.GetLeaseExpiresAt() == nil {
		return fmt.Errorf("renew tenant serving lease: expiration required")
	}
	if err := update.GetLeaseExpiresAt().CheckValid(); err != nil {
		return fmt.Errorf("renew tenant serving lease: invalid expiration: %w", err)
	}

	now := g.now()
	expiresAt := update.GetLeaseExpiresAt().AsTime()
	if !expiresAt.After(now) || expiresAt.After(now.Add(maxServingLease)) {
		return fmt.Errorf("renew tenant serving lease: expiration outside allowed window")
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.requireTenantLocked(tenantID); err != nil {
		return err
	}
	if g.restriction != nil {
		return &TenantServingRestrictedError{Restriction: *g.restriction}
	}
	g.leaseExpiresAt = expiresAt
	return nil
}

// Restrict applies a durable, monotonic restriction. Replays are idempotent;
// an equal epoch with different authority fails closed.
func (g *TenantServingGate) Restrict(tenantID string, update *apiv1.TenantServingStateUpdate) error {
	restriction, err := restrictionFromUpdate(update)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.requireTenantLocked(tenantID); err != nil {
		return err
	}
	if g.restriction != nil {
		if restriction.Epoch < g.restriction.Epoch {
			return nil
		}
		if restriction.Epoch == g.restriction.Epoch {
			if restriction == *g.restriction {
				return nil
			}
			return fmt.Errorf("restrict tenant serving: conflicting authority at epoch %d", restriction.Epoch)
		}
	}
	g.restriction = &restriction
	g.leaseExpiresAt = time.Time{}
	return nil
}

// RequireActive denies when tenant scope differs, a restriction is present,
// or the latest active lease is missing or expired.
func (g *TenantServingGate) RequireActive(tenantID string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if err := g.requireTenantLocked(tenantID); err != nil {
		return err
	}
	if g.restriction != nil {
		return &TenantServingRestrictedError{Restriction: *g.restriction}
	}
	if !g.now().Before(g.leaseExpiresAt) {
		return ErrTenantServingLeaseUnavailable
	}
	return nil
}

func (g *TenantServingGate) requireTenantLocked(tenantID string) error {
	if g.tenantID == "" {
		return ErrTenantServingLeaseUnavailable
	}
	if tenantID != "" && tenantID != g.tenantID {
		return fmt.Errorf("tenant %q does not match bound tenant: %w", tenantID, ErrTenantServingScopeMismatch)
	}
	return nil
}

func restrictionFromUpdate(update *apiv1.TenantServingStateUpdate) (TenantServingRestriction, error) {
	if update == nil || update.GetState() != apiv1.TenantServingState_TENANT_SERVING_STATE_RESTRICTED {
		return TenantServingRestriction{}, fmt.Errorf("restrict tenant serving: restricted update required")
	}
	if update.GetLeaseExpiresAt() != nil || update.GetServingChallenge() != "" {
		return TenantServingRestriction{}, fmt.Errorf("restrict tenant serving: restriction contains active lease")
	}
	if update.GetEpoch() < 1 || update.GetAuthorityAppendOrdinal() < 1 {
		return TenantServingRestriction{}, fmt.Errorf("restrict tenant serving: positive epoch and authority ordinal required")
	}
	if _, err := ulid.ParseStrict(update.GetRestrictionRequestId()); err != nil {
		return TenantServingRestriction{}, fmt.Errorf("restrict tenant serving: invalid request ID: %w", err)
	}
	if _, err := ulid.ParseStrict(update.GetAuthorityEventId()); err != nil {
		return TenantServingRestriction{}, fmt.Errorf("restrict tenant serving: invalid authority event ID: %w", err)
	}
	if !validRestrictionReason(update.GetRestrictionReason()) {
		return TenantServingRestriction{}, fmt.Errorf("restrict tenant serving: invalid reason")
	}
	return TenantServingRestriction{
		Epoch:                  update.GetEpoch(),
		RequestID:              update.GetRestrictionRequestId(),
		Reason:                 update.GetRestrictionReason(),
		AuthorityEventID:       update.GetAuthorityEventId(),
		AuthorityAppendOrdinal: update.GetAuthorityAppendOrdinal(),
	}, nil
}

func validRestrictionReason(reason string) bool {
	switch reason {
	case "admitted_target_missing", "admitted_source_generation_missing", "admitted_model_revision_missing":
		return true
	default:
		return false
	}
}
