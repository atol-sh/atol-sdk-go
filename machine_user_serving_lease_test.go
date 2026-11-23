package sdk_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "atol.sh/sdk-go"
)

const (
	servingTenant    = "tenant-1"
	servingKeyID     = "key-1"
	servingSecret    = "secret-1"
	servingLeasePath = "/atol.api.v1.MachineUserService/GetTenantServingLease"
	servingAsOf      = "2026-11-22T04:00:00Z"
	servingExpires   = "2026-11-22T04:00:30Z"
)

func TestMachineUserClientServingLeaseSignsRequestAndUsesSendTime(t *testing.T) {
	t.Parallel()
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	received := make(chan time.Time, 1)
	client := servingLeaseClient(t, func(w http.ResponseWriter, r *http.Request) {
		received <- time.Now()
		if r.URL.Path != servingLeasePath || r.Method != http.MethodPost || r.Header.Get("X-Atol-Org-Id") != servingTenant {
			t.Error("serving lease request has the wrong method, path, or tenant header")
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Connect-Protocol-Version") != "1" {
			t.Error("serving lease request omitted the Connect JSON headers")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read serving lease request: %v", err)
		}
		var request struct {
			OrgID            string `json:"orgId"`
			ServingChallenge string `json:"servingChallenge"`
		}
		if err := json.Unmarshal(body, &request); err != nil || request.OrgID != servingTenant || request.ServingChallenge != challenge {
			t.Errorf("serving lease body does not match the tenant and challenge: %v", err)
		}
		verifyServingLeaseHMAC(t, r, body)
		if err := json.NewEncoder(w).Encode(activeServingResponse(challenge)); err != nil {
			t.Errorf("encode serving lease response: %v", err)
		}
	})

	before := time.Now()
	lease, err := client.GetTenantServingLease(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if lease.TenantID != servingTenant || lease.State != sdk.MachineTenantServingStateActive || lease.Epoch != 0 || lease.ServingChallenge != challenge {
		t.Fatalf("serving lease = %+v, want active epoch zero and matching tenant and challenge", lease)
	}
	if ttl := lease.LeaseExpiresAt.Sub(lease.AsOf); ttl != 30*time.Second {
		t.Errorf("lease TTL = %v, want 30s", ttl)
	}
	if min, max := before.Add(30*time.Second), (<-received).Add(30*time.Second); lease.Deadline.Before(min) || lease.Deadline.After(max) {
		t.Errorf("lease deadline = %v, want in [%v, %v]", lease.Deadline, min, max)
	}
}

func TestMachineUserClientServingLeaseRestricted(t *testing.T) {
	t.Parallel()
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	response := activeServingResponse(challenge)
	response["state"] = sdk.MachineTenantServingStateRestricted
	response["epoch"] = "9223372036854775807"
	delete(response, "leaseExpiresAt")
	client := servingLeaseResponseClient(t, response)
	lease, err := client.GetTenantServingLease(t.Context(), challenge)
	if err != nil {
		t.Fatal(err)
	}
	if lease.State != sdk.MachineTenantServingStateRestricted || lease.Epoch != math.MaxInt64 || !lease.LeaseExpiresAt.IsZero() || !lease.Deadline.IsZero() {
		t.Fatalf("serving lease = %+v, want restricted at the exact epoch without expiry", lease)
	}
}

func TestMachineUserClientServingLeaseRejectsMalformedResponses(t *testing.T) {
	t.Parallel()
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name    string
		replace map[string]any
		omit    string
	}{
		{name: "wrong tenant", replace: map[string]any{"tenantId": "tenant-2"}},
		{name: "wrong challenge", replace: map[string]any{"servingChallenge": "another"}},
		{name: "unknown state", replace: map[string]any{"state": "TENANT_SERVING_STATE_UNSPECIFIED"}},
		{name: "missing epoch", omit: "epoch"},
		{name: "negative epoch", replace: map[string]any{"epoch": "-1"}},
		{name: "overflowing epoch", replace: map[string]any{"epoch": "9223372036854775808"}},
		{name: "missing observation time", omit: "asOf"},
		{name: "invalid observation time", replace: map[string]any{"asOf": "invalid"}},
		{name: "missing active expiry", omit: "leaseExpiresAt"},
		{name: "zero ttl", replace: map[string]any{"leaseExpiresAt": servingAsOf}},
		{name: "too long", replace: map[string]any{"leaseExpiresAt": "2026-11-22T04:00:30.000000001Z"}},
		{name: "elapsed ttl", replace: map[string]any{"leaseExpiresAt": "2026-11-22T04:00:00.000000001Z"}},
		{name: "restricted expiry", replace: map[string]any{"state": sdk.MachineTenantServingStateRestricted, "epoch": "1"}},
		{name: "restricted epoch zero", replace: map[string]any{"state": sdk.MachineTenantServingStateRestricted}, omit: "leaseExpiresAt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response := activeServingResponse(challenge)
			for field, value := range tt.replace {
				response[field] = value
			}
			delete(response, tt.omit)
			client := servingLeaseResponseClient(t, response)
			if lease, err := client.GetTenantServingLease(t.Context(), challenge); err == nil || lease != nil {
				t.Errorf("serving lease = %+v, %v, want refusal", lease, err)
			}
		})
	}
}

func TestMachineUserClientServingLeaseRejectsNoncanonicalChallenge(t *testing.T) {
	t.Parallel()
	client := servingLeaseClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("sent a request with an invalid serving challenge")
		w.WriteHeader(http.StatusBadRequest)
	})
	for _, challenge := range []string{"", strings.Repeat("A", 43) + "=", strings.Repeat("A", 42) + "B"} {
		if lease, err := client.GetTenantServingLease(t.Context(), challenge); err == nil || lease != nil {
			t.Errorf("serving lease for challenge %q = %+v, %v, want refusal", challenge, lease, err)
		}
	}
}

func TestMachineUserClientServingLeasePreservesServiceErrors(t *testing.T) {
	t.Parallel()
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, result := range []struct {
		code   string
		status int
	}{
		{code: "unauthenticated", status: http.StatusUnauthorized},
		{code: "permission_denied", status: http.StatusForbidden},
		{code: "invalid_argument", status: http.StatusBadRequest},
		{code: "unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(result.code, func(t *testing.T) {
			t.Parallel()
			client := servingLeaseClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(result.status)
				if err := json.NewEncoder(w).Encode(map[string]string{"code": result.code}); err != nil {
					t.Errorf("encode service error: %v", err)
				}
			})
			lease, err := client.GetTenantServingLease(t.Context(), challenge)
			var serviceErr *sdk.ServiceError
			if lease != nil || !errors.As(err, &serviceErr) || serviceErr.Code != result.code || serviceErr.Status != result.status {
				t.Errorf("serving lease = %+v, %v, want service error %d %s", lease, err, result.status, result.code)
			}
		})
	}
}

func activeServingResponse(challenge string) map[string]any {
	return map[string]any{
		"tenantId": servingTenant, "servingChallenge": challenge,
		"state": sdk.MachineTenantServingStateActive, "epoch": "0",
		"asOf": servingAsOf, "leaseExpiresAt": servingExpires,
	}
}

func servingLeaseClient(t *testing.T, handler http.HandlerFunc) *sdk.MachineUserClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := sdk.NewMachineUserClient(sdk.Config{
		ControlPlaneURL: server.URL, StoreID: servingTenant, KeyID: servingKeyID, SecretKey: servingSecret,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func servingLeaseResponseClient(t *testing.T, response map[string]any) *sdk.MachineUserClient {
	t.Helper()
	return servingLeaseClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode serving response: %v", err)
		}
	})
}

func verifyServingLeaseHMAC(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	authorization, ok := strings.CutPrefix(r.Header.Get("Authorization"), "ATOL-HMAC-SHA256 ")
	if !ok {
		t.Error("serving lease request did not use Atol HMAC")
		return
	}
	fields := map[string]string{}
	for part := range strings.SplitSeq(authorization, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			fields[key] = value
		}
	}
	hash := sha256.Sum256(body)
	canonical := "ATOL-HMAC-SHA256\n" + fields["Timestamp"] + "\nPOST\n" + r.URL.Path + "\n" + hex.EncodeToString(hash[:])
	mac := hmac.New(sha256.New, []byte(servingSecret))
	_, _ = mac.Write([]byte(canonical))
	if fields["Credential"] != servingKeyID || fields["Timestamp"] == "" || !hmac.Equal([]byte(fields["Signature"]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Error("scoped credential did not sign the exact serving lease request")
	}
}
