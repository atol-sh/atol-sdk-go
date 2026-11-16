package sdk_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "atol.sh/sdk-go"
)

func TestMachineUserClientCallsScopedService(t *testing.T) {
	t.Parallel()
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "ATOL-HMAC-SHA256 Credential=key-1,") {
			t.Error("request was not signed with the scoped machine key")
		}
		if r.Header.Get("Connect-Protocol-Version") != "1" {
			t.Error("request omitted Connect protocol version")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		fields := map[string]string{}
		for _, part := range strings.Split(strings.TrimPrefix(authorization, "ATOL-HMAC-SHA256 "), ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok {
				fields[key] = value
			}
		}
		hash := sha256.Sum256(body)
		canonical := "ATOL-HMAC-SHA256\n" + fields["Timestamp"] + "\nPOST\n" + r.URL.Path + "\n" + hex.EncodeToString(hash[:])
		mac := hmac.New(sha256.New, []byte("secret-1"))
		_, _ = mac.Write([]byte(canonical))
		if !hmac.Equal([]byte(fields["Signature"]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			t.Error("HMAC does not cover the exact JSON request body and RPC path")
		}
		var request map[string]any
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request["orgId"] != "tenant-1" {
			t.Errorf("request orgId = %v, want tenant-1", request["orgId"])
		}
		method := strings.TrimPrefix(r.URL.Path, "/atol.api.v1.MachineUserService/")
		methods = append(methods, method)
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case "CreateUser":
			if request["idempotencyKey"] != "stable-key-123456" {
				t.Errorf("create idempotency key = %v", request["idempotencyKey"])
			}
			_, _ = w.Write([]byte(`{"user":{"id":"user-1","orgId":"tenant-1","email":"a@example.com"}}`))
		case "GetUser", "UpdateDisplayName":
			_, _ = w.Write([]byte(`{"user":{"id":"user-1","orgId":"tenant-1","email":"a@example.com"}}`))
		case "ListUsers":
			_, _ = w.Write([]byte(`{"users":[{"id":"user-1","orgId":"tenant-1"}],"page":{"nextPageToken":"next","totalCount":1}}`))
		case "StartInvitation":
			_, _ = w.Write([]byte(`{"userId":"user-1","deliveryState":"pending","expiresAt":"2026-11-17T00:00:00Z"}`))
		case "StartPasswordReset":
			if request["idempotencyKey"] != "reset-key-1234567" || request["userId"] != "user-1" {
				t.Errorf("reset request = %v", request)
			}
			_, _ = w.Write([]byte(`{"deliveryState":"pending","expiresAt":"2026-11-17T00:00:00Z"}`))
		case "DeactivateUser", "ReactivateUser":
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected method %q", method)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client, err := sdk.NewMachineUserClient(sdk.Config{ControlPlaneURL: server.URL, StoreID: "tenant-1", KeyID: "key-1", SecretKey: "secret-1"}, nil)
	if err != nil {
		t.Fatalf("new machine user client: %v", err)
	}
	ctx := context.Background()
	for range 2 {
		user, err := client.CreateUser(ctx, sdk.CreateMachineUserInput{Email: "a@example.com", IdempotencyKey: "stable-key-123456"})
		if err != nil || user.ID != "user-1" {
			t.Fatalf("create user = %+v, %v", user, err)
		}
	}
	if _, err := client.GetUser(ctx, "user-1"); err != nil {
		t.Fatalf("get user: %v", err)
	}
	page, err := client.ListUsers(ctx, 20, "")
	if err != nil || len(page.Users) != 1 || page.NextPageToken != "next" {
		t.Fatalf("list users = %+v, %v", page, err)
	}
	if _, err := client.UpdateDisplayName(ctx, "user-1", "Alice"); err != nil {
		t.Fatalf("update display name: %v", err)
	}
	if err := client.DeactivateUser(ctx, "user-1"); err != nil {
		t.Fatalf("deactivate user: %v", err)
	}
	if err := client.ReactivateUser(ctx, "user-1"); err != nil {
		t.Fatalf("reactivate user: %v", err)
	}
	invitation, err := client.StartInvitation(ctx, "user-1", "invite-key-123456")
	if err != nil || invitation.DeliveryState != "pending" {
		t.Fatalf("start invitation = %+v, %v", invitation, err)
	}
	reset, err := client.StartPasswordReset(ctx, "user-1", "reset-key-1234567")
	if err != nil || reset.DeliveryState != "pending" || reset.ExpiresAt.IsZero() {
		t.Fatalf("start password reset = %+v, %v", reset, err)
	}
	if got := strings.Join(methods, ","); got != "CreateUser,CreateUser,GetUser,ListUsers,UpdateDisplayName,DeactivateUser,ReactivateUser,StartInvitation,StartPasswordReset" {
		t.Errorf("methods = %q", got)
	}
}

func TestMachineUserClientRejectsUnsafeInputAndReportsCode(t *testing.T) {
	t.Parallel()
	if _, err := sdk.NewMachineUserClient(sdk.Config{ControlPlaneURL: "http://api.example.com", StoreID: "t", KeyID: "k", SecretKey: "s"}, nil); err == nil {
		t.Fatal("non-loopback plaintext endpoint accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"already_exists","message":"private detail"}`))
	}))
	t.Cleanup(server.Close)
	client, err := sdk.NewMachineUserClient(sdk.Config{ControlPlaneURL: server.URL, StoreID: "t", KeyID: "k", SecretKey: "s"}, nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := client.CreateUser(context.Background(), sdk.CreateMachineUserInput{Email: "a@example.com", IdempotencyKey: "short"}); err == nil {
		t.Fatal("short idempotency key accepted")
	}
	_, err = client.GetUser(context.Background(), "u")
	var serviceErr *sdk.ServiceError
	if !errors.As(err, &serviceErr) || serviceErr.Status != http.StatusConflict || serviceErr.Code != "already_exists" {
		t.Fatalf("service error = %v, want conflict/already_exists", err)
	}
	if strings.Contains(err.Error(), "private detail") {
		t.Fatal("service error exposed server body")
	}
}
