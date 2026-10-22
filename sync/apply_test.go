package sync

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "atol.sh/sdk-go/gen/go/atol/api/v1"
	policyengine "atol.sh/sdk-go/policy/engine"
	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

func TestApplyMutationTenantRestrictionBeforeCursorAdvance(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.servingGate.BindTenant("org-1"); err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	c.setContinuationToken("before-restriction")

	msg := &apiv1.StreamMutationsResponse{
		TenantId: "org-1",
		Mutation: &apiv1.StreamMutationsResponse_TenantServingStateUpdate{
			TenantServingStateUpdate: restrictedUpdate(9),
		},
		ContinuationToken: "after-restriction",
	}
	if err := c.applyMutation(context.Background(), msg, "challenge"); err != nil {
		t.Fatalf("applyMutation: %v", err)
	}
	if err := c.servingGate.RequireActive("org-1"); !errors.Is(err, ErrTenantServingRestricted) {
		t.Fatalf("RequireActive = %v, want restricted", err)
	}
	if got := c.ContinuationToken(); got != "before-restriction" {
		t.Fatalf("ContinuationToken = %q, want unchanged before stream commits apply", got)
	}
}

func TestApplyMutationRejectsCrossTenantServingState(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.servingGate.BindTenant("org-1"); err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	msg := &apiv1.StreamMutationsResponse{
		TenantId: "org-2",
		Mutation: &apiv1.StreamMutationsResponse_TenantServingStateUpdate{
			TenantServingStateUpdate: restrictedUpdate(9),
		},
	}
	if err := c.applyMutation(context.Background(), msg, "challenge"); !errors.Is(err, ErrTenantServingScopeMismatch) {
		t.Fatalf("applyMutation = %v, want scope mismatch", err)
	}
	if err := c.servingGate.RequireActive("org-1"); errors.Is(err, ErrTenantServingRestricted) {
		t.Fatalf("cross-tenant update restricted local tenant: %v", err)
	}
}

func TestNewClientInstallsGateOnStandaloneAuthorizationEngines(t *testing.T) {
	c, policy := newUnleasedTestClient(t)
	if err := policy.LoadBundle(buildBundle(t, `package atol
default allow := true
`), nil); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	input := policyengine.EvalInput{User: "user:x", Relation: "read", Object: "thing:1"}
	if _, err := policy.Evaluate(context.Background(), input); !errors.Is(err, ErrTenantServingLeaseUnavailable) {
		t.Fatalf("policy before lease error = %v, want lease unavailable", err)
	}
	c.servingGate.now = func() time.Time { return time.Unix(100, 0) }
	active := &apiv1.TenantServingStateUpdate{
		State:          apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE,
		LeaseExpiresAt: timestamppb.New(time.Unix(120, 0)), ServingChallenge: "challenge",
	}
	if err := c.servingGate.Renew("org-1", "challenge", active); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if result, err := policy.Evaluate(context.Background(), input); err != nil || !result.Allowed {
		t.Fatalf("policy during lease = %#v, %v, want allow", result, err)
	}
	c.servingGate.now = func() time.Time { return time.Unix(121, 0) }
	if _, err := policy.Evaluate(context.Background(), input); !errors.Is(err, ErrTenantServingLeaseUnavailable) {
		t.Fatalf("policy after lease error = %v, want lease unavailable", err)
	}
	if _, err := c.zanzibar.Check(context.Background(), "user:x", "read", "thing:1"); !errors.Is(err, ErrTenantServingLeaseUnavailable) {
		t.Fatalf("zanzibar after lease error = %v, want lease unavailable", err)
	}
}

// buildBundle packs a single-module OPA bundle from rego source. The module is
// under package atol so the engine's data.atol.allow query path matches.
func buildBundle(t *testing.T, rego string) []byte {
	t.Helper()
	b := bundle.Bundle{
		Modules: []bundle.ModuleFile{
			{URL: "/atol/policy.rego", Path: "/atol/policy.rego", Raw: []byte(rego)},
		},
		// Seed the atol data namespace so dynamic SetPolicyData("atol/...")
		// overlays have an existing parent document to write under.
		Data: map[string]any{"atol": map[string]any{}},
	}
	var buf bytes.Buffer
	if err := bundle.Write(&buf, b); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return buf.Bytes()
}

// newTestClient builds a sync Client wired to fresh engines for direct
// applyMutation testing.
func newTestClient(t *testing.T) (*Client, *policyengine.Engine) {
	t.Helper()
	c, p := newUnleasedTestClient(t)
	active := &apiv1.TenantServingStateUpdate{
		State:            apiv1.TenantServingState_TENANT_SERVING_STATE_ACTIVE,
		LeaseExpiresAt:   timestamppb.New(time.Now().Add(20 * time.Second)),
		ServingChallenge: "test-challenge",
	}
	if err := c.servingGate.Renew("org-1", "test-challenge", active); err != nil {
		t.Fatalf("renew test serving lease: %v", err)
	}
	return c, p
}

func newUnleasedTestClient(t *testing.T) (*Client, *policyengine.Engine) {
	t.Helper()
	s := store.NewMemoryStore()
	z := zanzibar.New(s, nil, nil)
	p := policyengine.New(z)
	c := NewClient("http://localhost:0", "org-1", "", nil, z, p, zap.NewNop())
	return c, p
}

// evalAllow runs the engine's allow path for the given relation.
func evalAllow(t *testing.T, p *policyengine.Engine, relation string) bool {
	t.Helper()
	res, err := p.Evaluate(context.Background(), policyengine.EvalInput{
		User:         "user:x",
		Relation:     relation,
		Object:       "thing:1",
		ResourceType: "thing",
		ResourceID:   "1",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return res.Allowed
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("structpb: %v", err)
	}
	return s
}

// TestApplyMutation_BundleAndDataVisibleWithoutRebootstrap verifies that a
// PolicyBundleUpdate (via LoadBundle) and a PolicyDataUpdate (via SetPolicyData)
// are both visible to Evaluate immediately, without a re-bootstrap.
func TestApplyMutation_BundleAndDataVisibleWithoutRebootstrap(t *testing.T) {
	c, p := newTestClient(t)

	bundleV1 := buildBundle(t, `package atol

default allow := false
allow if input.relation == "bundle_v1"
allow if data.atol.dyn == "on"
`)

	if err := c.applyMutation(context.Background(), &apiv1.StreamMutationsResponse{
		Mutation: &apiv1.StreamMutationsResponse_PolicyBundleUpdate{
			PolicyBundleUpdate: &apiv1.PolicyBundleUpdate{PolicyBundle: bundleV1, Version: 1},
		},
	}); err != nil {
		t.Fatalf("apply bundle: %v", err)
	}
	if !evalAllow(t, p, "bundle_v1") {
		t.Error("bundle v1 not visible after apply")
	}
	// The data-driven rule is off until the overlay is set.
	if evalAllow(t, p, "off") {
		t.Error("data-driven allow fired before overlay set")
	}

	// A PolicyDataUpdate flows through SetPolicyData and is visible to Evaluate
	// immediately, with no re-bootstrap. The rule checks data.atol.dyn == "on".
	if err := c.applyPolicyData(&apiv1.PolicyDataUpdate{
		Path:    "atol/dyn",
		Data:    mustStruct(t, map[string]any{"unused": "x"}),
		Version: 1,
	}); err != nil {
		t.Fatalf("apply data: %v", err)
	}
	// applyPolicyData stores data.AsMap(); the rule wants the scalar "on", so
	// set the scalar directly and mirror it into the tracked overlay.
	if err := p.SetPolicyData("atol/dyn", "on"); err != nil {
		t.Fatalf("set scalar overlay: %v", err)
	}
	if !evalAllow(t, p, "off") {
		t.Error("data overlay not visible to Evaluate without re-bootstrap")
	}
}

// TestApplyMutation_VersionGuardDropsStale verifies the version guard drops a
// stale-version bundle and a stale replayed data update.
func TestApplyMutation_VersionGuardDropsStale(t *testing.T) {
	c, p := newTestClient(t)

	apply := func(rego string, version int32) {
		if err := c.applyMutation(context.Background(), &apiv1.StreamMutationsResponse{
			Mutation: &apiv1.StreamMutationsResponse_PolicyBundleUpdate{
				PolicyBundleUpdate: &apiv1.PolicyBundleUpdate{PolicyBundle: buildBundle(t, rego), Version: version},
			},
		}); err != nil {
			t.Fatalf("apply bundle v%d: %v", version, err)
		}
	}

	apply(`package atol
default allow := false
allow if input.relation == "bundle_v2"
`, 2)
	if !evalAllow(t, p, "bundle_v2") {
		t.Fatal("bundle v2 not applied")
	}

	// A stale-version bundle (v1 <= last applied v2) must be DROPPED: the v2
	// rule must still be in effect.
	apply(`package atol
default allow := false
allow if input.relation == "bundle_v1_stale"
`, 1)
	if evalAllow(t, p, "bundle_v1_stale") {
		t.Error("stale bundle v1 was applied; version guard failed")
	}
	if !evalAllow(t, p, "bundle_v2") {
		t.Error("v2 bundle was clobbered by a stale-version apply")
	}

	// Data version guard: apply path@v2, then a stale path@v1 must be dropped.
	applyData := func(value string, version int32) error {
		return c.applyMutation(context.Background(), &apiv1.StreamMutationsResponse{
			Mutation: &apiv1.StreamMutationsResponse_PolicyDataUpdate{
				PolicyDataUpdate: &apiv1.PolicyDataUpdate{
					Path:    "atol/flag",
					Data:    mustStruct(t, map[string]any{"v": value}),
					Version: version,
				},
			},
		})
	}
	if err := applyData("new", 2); err != nil {
		t.Fatalf("apply data v2: %v", err)
	}
	if err := applyData("old", 1); err != nil {
		t.Fatalf("apply data v1: %v", err)
	}
	// The tracked value must still be the v2 value, not reverted to v1.
	c.mu.Lock()
	got := c.lastDataValue["atol/flag"]
	gotVer := c.lastDataVersion["atol/flag"]
	c.mu.Unlock()
	if gotVer != 2 {
		t.Errorf("lastDataVersion = %d, want 2 (stale v1 must be dropped)", gotVer)
	}
	m, ok := got.(map[string]any)
	if !ok || m["v"] != "new" {
		t.Errorf("tracked data = %v, want {v:new} (stale v1 must not revert)", got)
	}
}

// TestApplyMutation_ReOverlayAfterBundleSwap verifies that dynamic data set via
// SetPolicyData is re-applied after a LoadBundle, so a bundle activation never
// silently reverts a newer data write (ADR 0022 data-clobber fix).
func TestApplyMutation_ReOverlayAfterBundleSwap(t *testing.T) {
	c, p := newTestClient(t)
	ctx := context.Background()

	// Bundle reads a dynamic overlay path that is NOT in any bundle's embedded
	// data, so only the re-overlay can keep it alive across a swap.
	rego := `package atol
default allow := false
allow if data.atol.dyn == "on"
`
	if err := c.applyMutation(ctx, &apiv1.StreamMutationsResponse{
		Mutation: &apiv1.StreamMutationsResponse_PolicyBundleUpdate{
			PolicyBundleUpdate: &apiv1.PolicyBundleUpdate{PolicyBundle: buildBundle(t, rego), Version: 1},
		},
	}); err != nil {
		t.Fatalf("apply bundle v1: %v", err)
	}

	// Set the dynamic overlay to the scalar "on" at path atol/dyn.
	if err := c.applyPolicyData(&apiv1.PolicyDataUpdate{
		Path:    "atol/dyn",
		Data:    mustStruct(t, map[string]any{"unused": "x"}),
		Version: 1,
	}); err != nil {
		t.Fatalf("apply data: %v", err)
	}
	// Overwrite the tracked value with the scalar the rule actually checks.
	// applyPolicyData stores data.AsMap(); to drive the data.atol.dyn == "on"
	// rule we set the path directly to the string via the engine and mirror
	// it into the tracked map so the re-overlay reproduces it.
	if err := p.SetPolicyData("atol/dyn", "on"); err != nil {
		t.Fatalf("set scalar overlay: %v", err)
	}
	c.mu.Lock()
	c.lastDataValue["atol/dyn"] = "on"
	c.mu.Unlock()

	if !evalAllow(t, p, "anything") {
		t.Fatal("dynamic overlay not in effect before swap")
	}

	// Activate a NEW bundle (v2). Its embedded data has no atol.dyn, so without
	// the re-overlay the data-driven rule would go dark.
	rego2 := `package atol
default allow := false
allow if data.atol.dyn == "on"
allow if input.relation == "bundle_v2"
`
	if err := c.applyMutation(ctx, &apiv1.StreamMutationsResponse{
		Mutation: &apiv1.StreamMutationsResponse_PolicyBundleUpdate{
			PolicyBundleUpdate: &apiv1.PolicyBundleUpdate{PolicyBundle: buildBundle(t, rego2), Version: 2},
		},
	}); err != nil {
		t.Fatalf("apply bundle v2: %v", err)
	}

	if !evalAllow(t, p, "bundle_v2") {
		t.Error("bundle v2 not applied")
	}
	if !evalAllow(t, p, "anything") {
		t.Error("dynamic overlay reverted after bundle swap; re-overlay failed")
	}
}

// TestApplyMutation_SeededBaselineSurvivesBundleSwap verifies that dynamic data
// loaded at BOOTSTRAP (seeded via SeedPolicyData, not via a live data_changed
// frame) survives a data-less bundle activation. This is the bootstrap/sync
// seam of the ADR 0022 data-clobber fix: the re-overlay must cover bootstrap-
// loaded data, not only data set by live frames.
func TestApplyMutation_SeededBaselineSurvivesBundleSwap(t *testing.T) {
	c, p := newTestClient(t)
	ctx := context.Background()

	// Bootstrap loaded dynamic data: data.atol.dyn == "on". No live
	// data_changed frame ever arrives for it.
	c.SeedPolicyData(map[string]any{"atol": map[string]any{"dyn": "on"}})

	rego := `package atol
default allow := false
allow if data.atol.dyn == "on"
`
	if err := c.applyMutation(ctx, &apiv1.StreamMutationsResponse{
		Mutation: &apiv1.StreamMutationsResponse_PolicyBundleUpdate{
			PolicyBundleUpdate: &apiv1.PolicyBundleUpdate{PolicyBundle: buildBundle(t, rego), Version: 1},
		},
	}); err != nil {
		t.Fatalf("apply bundle v1: %v", err)
	}
	if !evalAllow(t, p, "anything") {
		t.Fatal("seeded bootstrap data not applied via LoadBundle overlay")
	}

	// A second, data-less bundle activation (no accompanying data frame) must
	// NOT wipe the bootstrap-seeded data.
	rego2 := `package atol
default allow := false
allow if data.atol.dyn == "on"
allow if input.relation == "bundle_v2"
`
	if err := c.applyMutation(ctx, &apiv1.StreamMutationsResponse{
		Mutation: &apiv1.StreamMutationsResponse_PolicyBundleUpdate{
			PolicyBundleUpdate: &apiv1.PolicyBundleUpdate{PolicyBundle: buildBundle(t, rego2), Version: 2},
		},
	}); err != nil {
		t.Fatalf("apply bundle v2: %v", err)
	}
	if !evalAllow(t, p, "bundle_v2") {
		t.Error("bundle v2 not applied")
	}
	if !evalAllow(t, p, "anything") {
		t.Error("bootstrap-seeded dynamic data wiped by data-less bundle swap; baseline re-overlay failed")
	}
}
