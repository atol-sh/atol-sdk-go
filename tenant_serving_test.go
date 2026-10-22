package sdk

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	zstore "atol.sh/sdk-go/zanzibar/store"
)

const tenantServingTestTenantID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func TestTenantServingGateRejectsConfiguredControlPlaneWithoutLiveSync(t *testing.T) {
	_, err := New(Config{
		ControlPlaneURL: "https://control.example",
		StoreID:         tenantServingTestTenantID,
		DisableSync:     true,
	})
	if err == nil {
		t.Fatal("New with configured control plane and DisableSync = nil, want error")
	}
}

func TestTenantServingGateRejectsCrossTenantOPAPath(t *testing.T) {
	a, err := New(Config{ControlPlaneURL: "https://control.example", StoreID: tenantServingTestTenantID})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	if err := a.servingGate.BindTenant(tenantServingTestTenantID); err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	active := &apiv1.TenantServingStateUpdate{
		State:          apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE,
		LeaseExpiresAt: timestamppb.New(time.Now().Add(20 * time.Second)), ServingChallenge: "challenge",
	}
	if err := a.servingGate.Renew(tenantServingTestTenantID, "challenge", active); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	ctx := zstore.ContextWithTenant(context.Background(), "01ARZ3NDEKTSV4RRFFQ69G5FAY")
	if _, err := a.Can(ctx, "user:alice", "viewer", "document:doc-1"); !errors.Is(err, ErrTenantServingScopeMismatch) {
		t.Fatalf("cross-tenant Can error = %v, want scope mismatch", err)
	}
}

func TestTenantServingGateRunsBeforeAuthorization(t *testing.T) {
	a, err := New(Config{
		ControlPlaneURL: "https://control.example",
		StoreID:         tenantServingTestTenantID,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	if err := a.LoadModel(gateModel); err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	grantLocalForTest(t, a, "user:alice", "viewer", "document:doc-1")

	if _, err := a.Can(context.Background(), "user:alice", "viewer", "document:doc-1"); !errors.Is(err, ErrTenantServingLeaseUnavailable) {
		t.Fatalf("Can before lease = %v, want lease unavailable", err)
	}
	if err := a.servingGate.BindTenant(tenantServingTestTenantID); err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	active := &apiv1.TenantServingStateUpdate{
		State:            apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE,
		LeaseExpiresAt:   timestamppb.New(time.Now().Add(20 * time.Second)),
		ServingChallenge: "challenge",
	}
	if err := a.servingGate.Renew(tenantServingTestTenantID, "challenge", active); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	allowed, err := a.Can(context.Background(), "user:alice", "viewer", "document:doc-1")
	if err != nil {
		t.Fatalf("Can during lease: %v", err)
	}
	if !allowed {
		t.Fatal("Can during lease = false, want true")
	}
	if err := a.servingGate.Restrict(tenantServingTestTenantID, restrictedUpdate(1)); err != nil {
		t.Fatalf("Restrict: %v", err)
	}
	if _, err := a.Can(context.Background(), "user:alice", "viewer", "document:doc-1"); !errors.Is(err, ErrTenantServingRestricted) {
		t.Fatalf("Can after restriction = %v, want restricted", err)
	}
}

func restrictedUpdate(epoch int64) *apiv1.TenantServingStateUpdate {
	return &apiv1.TenantServingStateUpdate{
		Epoch:                  epoch,
		State:                  apiv1.TenantServingState_TENANT_SERVING_STATE_RESTRICTED,
		RestrictionRequestId:   "01ARZ3NDEKTSV4RRFFQ69G5FAW",
		RestrictionReason:      "admitted_target_missing",
		AuthorityEventId:       "01ARZ3NDEKTSV4RRFFQ69G5FAX",
		AuthorityAppendOrdinal: 7,
	}
}
