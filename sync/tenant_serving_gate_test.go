package sync

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
)

const (
	testTenantID  = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testRequestID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	testEventID   = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
)

func TestTenantServingGateLeaseIsChallengeBoundAndExpires(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	gate := NewTenantServingGate()
	gate.now = func() time.Time { return now }

	if err := gate.RequireActive(""); !errors.Is(err, ErrTenantServingLeaseUnavailable) {
		t.Fatalf("RequireActive before bind = %v, want lease unavailable", err)
	}
	if err := gate.BindTenant(testTenantID); err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	active := &apiv1.TenantServingStateUpdate{
		State:            apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE,
		LeaseExpiresAt:   timestamppb.New(now.Add(20 * time.Second)),
		ServingChallenge: "challenge",
	}
	if err := gate.Renew(testTenantID, "wrong", active); err == nil {
		t.Fatal("Renew with wrong challenge = nil, want error")
	}
	if err := gate.Renew(testTenantID, "challenge", active); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := gate.RequireActive(testTenantID); err != nil {
		t.Fatalf("RequireActive during lease: %v", err)
	}
	if err := gate.RequireActive("another-tenant"); !errors.Is(err, ErrTenantServingScopeMismatch) {
		t.Fatalf("RequireActive for another tenant = %v, want scope mismatch", err)
	}

	now = now.Add(20 * time.Second)
	if err := gate.RequireActive(testTenantID); !errors.Is(err, ErrTenantServingLeaseUnavailable) {
		t.Fatalf("RequireActive at expiration = %v, want lease unavailable", err)
	}
}

func TestTenantServingGateRestrictionIsStickyMonotonicAndIdempotent(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	gate := NewTenantServingGate()
	gate.now = func() time.Time { return now }
	if err := gate.BindTenant(testTenantID); err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	active := &apiv1.TenantServingStateUpdate{
		State:            apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE,
		LeaseExpiresAt:   timestamppb.New(now.Add(20 * time.Second)),
		ServingChallenge: "challenge",
	}
	if err := gate.Renew(testTenantID, "challenge", active); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	restricted := restrictedUpdate(4)
	if err := gate.Restrict(testTenantID, restricted); err != nil {
		t.Fatalf("Restrict: %v", err)
	}
	if err := gate.Restrict(testTenantID, restricted); err != nil {
		t.Fatalf("idempotent Restrict replay: %v", err)
	}
	if err := gate.RequireActive(testTenantID); !errors.Is(err, ErrTenantServingRestricted) {
		t.Fatalf("RequireActive after restriction = %v, want restricted", err)
	}
	if err := gate.Renew(testTenantID, "challenge", active); !errors.Is(err, ErrTenantServingRestricted) {
		t.Fatalf("Renew after restriction = %v, want restricted", err)
	}

	conflict := restrictedUpdate(4)
	conflict.RestrictionReason = "admitted_source_generation_missing"
	if err := gate.Restrict(testTenantID, conflict); err == nil {
		t.Fatal("conflicting restriction at same epoch = nil, want error")
	}
	if err := gate.Restrict(testTenantID, restrictedUpdate(3)); err != nil {
		t.Fatalf("older restriction should be an idempotent no-op: %v", err)
	}
}

func restrictedUpdate(epoch int64) *apiv1.TenantServingStateUpdate {
	return &apiv1.TenantServingStateUpdate{
		Epoch:                  epoch,
		State:                  apiv1.TenantServingState_TENANT_SERVING_STATE_RESTRICTED,
		RestrictionRequestId:   testRequestID,
		RestrictionReason:      "admitted_target_missing",
		AuthorityEventId:       testEventID,
		AuthorityAppendOrdinal: 7,
	}
}
