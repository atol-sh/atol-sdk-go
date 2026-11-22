package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	sdkhmac "atol.sh/sdk-go/hmac"
)

const machineUserServicePath = "/atol.api.v1.MachineUserService/"

// MachineUserClient calls Atol's tenant-scoped MachineUserService with a scoped
// API key. It does not use the embedded authorization engine or customer data.
type MachineUserClient struct {
	baseURL string
	orgID   string
	http    *http.Client
}

// MachineUser is the narrow user projection returned by MachineUserService.
type MachineUser struct {
	ID            string    `json:"id"`
	DisplayName   string    `json:"displayName"`
	Email         string    `json:"email"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"emailVerified"`
	OrgID         string    `json:"orgId"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// CreateMachineUserInput requires a caller-stable idempotency key. Reuse it on
// retries; a changed request with the same key is rejected by Atol.
type CreateMachineUserInput struct {
	Email          string
	DisplayName    string
	IdempotencyKey string
}

type MachineUserPage struct {
	Users         []MachineUser
	NextPageToken string
	TotalCount    int32
}

type MachineInvitation struct {
	UserID        string    `json:"userId"`
	DeliveryState string    `json:"deliveryState"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// MachineRevocations is a complete bounded snapshot of revoked session IDs.
// Treat a stale or future AsOf or a failed refresh as unavailable authorization state.
type MachineRevocations struct {
	RevokedSessionIDs []string  `json:"revokedSessionIds"`
	AsOf              time.Time `json:"asOf"`
}

// FreshAt reports whether the snapshot is no older than maxAge at now.
// Future timestamps are invalid so clock skew cannot extend the freshness window.
func (r *MachineRevocations) FreshAt(now time.Time, maxAge time.Duration) bool {
	if r == nil || r.AsOf.IsZero() || now.IsZero() || maxAge <= 0 {
		return false
	}
	return !r.AsOf.After(now) && !r.AsOf.Before(now.Add(-maxAge))
}

// MachinePasswordReset is the delivery status of a hosted one-use reset link.
// It contains no bearer token or user profile.
type MachinePasswordReset struct {
	DeliveryState string    `json:"deliveryState"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// NewMachineUserClient creates a service client without changing the caller's
// HTTP client. Config.StoreID must be the canonical tenant ID, not its slug,
// because the service returns canonical IDs for user records. A nil HTTP client
// uses a 15-second timeout and default transport.
func NewMachineUserClient(config Config, httpClient *http.Client) (*MachineUserClient, error) {
	baseURL, err := serviceBaseURL(config.ControlPlaneURL)
	if err != nil {
		return nil, err
	}
	if config.StoreID == "" || config.KeyID == "" || config.SecretKey == "" {
		return nil, errors.New("machine user client requires tenant ID and scoped API key")
	}
	client := serviceHTTPClient(httpClient)
	client.Transport = sdkhmac.NewTransport(config.KeyID, config.SecretKey, client.Transport)
	return &MachineUserClient{baseURL: baseURL, orgID: config.StoreID, http: client}, nil
}

func (c *MachineUserClient) call(ctx context.Context, method string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode machine user request: %w", err)
	}
	return serviceRequest(ctx, c.http, c.baseURL+machineUserServicePath+method, "application/json", body, output)
}

func (c *MachineUserClient) CreateUser(ctx context.Context, input CreateMachineUserInput) (*MachineUser, error) {
	if input.Email == "" || len(input.Email) > 254 || len(input.DisplayName) > 256 ||
		len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 {
		return nil, errors.New("create user requires bounded profile fields and a 16-128 character idempotency key")
	}
	var response struct {
		User *MachineUser `json:"user"`
	}
	err := c.call(ctx, "CreateUser", struct {
		OrgID          string `json:"orgId"`
		IdempotencyKey string `json:"idempotencyKey"`
		DisplayName    string `json:"displayName"`
		Email          string `json:"email"`
	}{c.orgID, input.IdempotencyKey, input.DisplayName, input.Email}, &response)
	if err != nil {
		return nil, err
	}
	if response.User == nil || response.User.ID == "" || response.User.OrgID != c.orgID {
		return nil, errors.New("Atol returned no created user")
	}
	return response.User, nil
}

func (c *MachineUserClient) GetUser(ctx context.Context, userID string) (*MachineUser, error) {
	if userID == "" {
		return nil, errors.New("user ID is required")
	}
	var response struct {
		User *MachineUser `json:"user"`
	}
	if err := c.call(ctx, "GetUser", struct {
		OrgID  string `json:"orgId"`
		UserID string `json:"userId"`
	}{c.orgID, userID}, &response); err != nil {
		return nil, err
	}
	if response.User == nil || response.User.ID != userID || response.User.OrgID != c.orgID {
		return nil, errors.New("Atol returned an unexpected user")
	}
	return response.User, nil
}

func (c *MachineUserClient) ListUsers(ctx context.Context, pageSize int32, pageToken string) (*MachineUserPage, error) {
	return c.listUsers(ctx, pageSize, pageToken, "")
}

// ListUsersSince lists users changed on or after updatedSince. Use the returned
// cursor for every page, then periodically run a full walk to catch deletions
// and transactions that committed after an incremental scan.
func (c *MachineUserClient) ListUsersSince(ctx context.Context, updatedSince time.Time, pageSize int32, pageToken string) (*MachineUserPage, error) {
	if updatedSince.IsZero() {
		return nil, errors.New("updated since is required")
	}
	return c.listUsers(ctx, pageSize, pageToken, updatedSince.UTC().Format(time.RFC3339Nano))
}

func (c *MachineUserClient) listUsers(ctx context.Context, pageSize int32, pageToken, updatedSince string) (*MachineUserPage, error) {
	if pageSize < 0 || pageSize > 500 {
		return nil, errors.New("page size must be between 0 and 500")
	}
	var response struct {
		Users []MachineUser `json:"users"`
		Page  struct {
			NextPageToken string `json:"nextPageToken"`
			TotalCount    int32  `json:"totalCount"`
		} `json:"page"`
	}
	if err := c.call(ctx, "ListUsers", struct {
		OrgID        string `json:"orgId"`
		UpdatedSince string `json:"updatedSince,omitempty"`
		Page         struct {
			PageSize  int32  `json:"pageSize"`
			PageToken string `json:"pageToken"`
		} `json:"page"`
	}{OrgID: c.orgID, UpdatedSince: updatedSince, Page: struct {
		PageSize  int32  `json:"pageSize"`
		PageToken string `json:"pageToken"`
	}{pageSize, pageToken}}, &response); err != nil {
		return nil, err
	}
	for _, user := range response.Users {
		if user.ID == "" || user.OrgID != c.orgID {
			return nil, errors.New("Atol returned a user outside the requested tenant")
		}
	}
	return &MachineUserPage{Users: response.Users, NextPageToken: response.Page.NextPageToken, TotalCount: response.Page.TotalCount}, nil
}

// ListRevokedSessions fetches the tenant's complete revocation snapshot using
// a key with sessions:revocations:read. Atol returns an error instead of a
// partial snapshot when the bounded response limit is exceeded.
func (c *MachineUserClient) ListRevokedSessions(ctx context.Context) (*MachineRevocations, error) {
	var response MachineRevocations
	if err := c.call(ctx, "ListRevokedSessions", struct {
		OrgID string `json:"orgId"`
	}{c.orgID}, &response); err != nil {
		return nil, err
	}
	if response.AsOf.IsZero() || len(response.RevokedSessionIDs) > 10_000 {
		return nil, errors.New("Atol returned an invalid revocation snapshot")
	}
	for _, id := range response.RevokedSessionIDs {
		if id == "" {
			return nil, errors.New("Atol returned an invalid revocation snapshot")
		}
	}
	return &response, nil
}

func (c *MachineUserClient) UpdateDisplayName(ctx context.Context, userID, displayName string) (*MachineUser, error) {
	if userID == "" || displayName == "" || len(displayName) > 256 {
		return nil, errors.New("user ID and a bounded display name are required")
	}
	var response struct {
		User *MachineUser `json:"user"`
	}
	if err := c.call(ctx, "UpdateDisplayName", struct {
		OrgID       string `json:"orgId"`
		UserID      string `json:"userId"`
		DisplayName string `json:"displayName"`
	}{c.orgID, userID, displayName}, &response); err != nil {
		return nil, err
	}
	if response.User == nil || response.User.ID != userID || response.User.OrgID != c.orgID {
		return nil, errors.New("Atol returned an unexpected user")
	}
	return response.User, nil
}

// DeactivateUser disables a tenant user and revokes their active sessions.
func (c *MachineUserClient) DeactivateUser(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("user ID is required")
	}
	var response struct{}
	return c.call(ctx, "DeactivateUser", struct {
		OrgID  string `json:"orgId"`
		UserID string `json:"userId"`
	}{c.orgID, userID}, &response)
}

// ReactivateUser restores a deactivated tenant user.
func (c *MachineUserClient) ReactivateUser(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.New("user ID is required")
	}
	var response struct{}
	return c.call(ctx, "ReactivateUser", struct {
		OrgID  string `json:"orgId"`
		UserID string `json:"userId"`
	}{c.orgID, userID}, &response)
}

// StartInvitation queues hosted enrollment for a user and registered OIDC
// client. The client's login-start URI receives the browser after enrollment.
func (c *MachineUserClient) StartInvitation(ctx context.Context, userID, clientID, idempotencyKey string) (*MachineInvitation, error) {
	if userID == "" || clientID == "" || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		return nil, errors.New("invitation requires user ID, client ID and a 16-128 character idempotency key")
	}
	var response MachineInvitation
	if err := c.call(ctx, "StartInvitation", struct {
		OrgID          string `json:"orgId"`
		UserID         string `json:"userId"`
		ClientID       string `json:"clientId"`
		IdempotencyKey string `json:"idempotencyKey"`
	}{c.orgID, userID, clientID, idempotencyKey}, &response); err != nil {
		return nil, err
	}
	if response.UserID != userID || response.DeliveryState == "" {
		return nil, errors.New("Atol returned an unexpected invitation")
	}
	return &response, nil
}

// StartPasswordReset queues a one-use reset email for an existing tenant user.
// Reuse the same idempotency key after an uncertain response.
func (c *MachineUserClient) StartPasswordReset(ctx context.Context, userID, idempotencyKey string) (*MachinePasswordReset, error) {
	if userID == "" || len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		return nil, errors.New("password reset requires user ID and a 16-128 character idempotency key")
	}
	var response MachinePasswordReset
	if err := c.call(ctx, "StartPasswordReset", struct {
		OrgID          string `json:"orgId"`
		UserID         string `json:"userId"`
		IdempotencyKey string `json:"idempotencyKey"`
	}{c.orgID, userID, idempotencyKey}, &response); err != nil {
		return nil, err
	}
	if response.DeliveryState == "" || response.ExpiresAt.IsZero() {
		return nil, errors.New("Atol returned an invalid password reset status")
	}
	return &response, nil
}
