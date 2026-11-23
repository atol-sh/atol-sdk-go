package sdk

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"time"
)

const (
	machineServingChallengeSize = 32
	machineServingLeaseLimit    = 30 * time.Second
)

// MachineTenantServingState is Atol's authoritative state for a tenant.
type MachineTenantServingState string

const (
	// MachineTenantServingStateActive permits serving while the lease is valid.
	MachineTenantServingStateActive MachineTenantServingState = "TENANT_SERVING_STATE_ACTIVE"
	// MachineTenantServingStateRestricted requires the verifier to stop serving.
	MachineTenantServingStateRestricted MachineTenantServingState = "TENANT_SERVING_STATE_RESTRICTED"
)

// MachineTenantServingLease is a challenge-bound snapshot for one tenant.
// Deadline uses the caller's local monotonic clock. LeaseExpiresAt is the
// server's timestamp and is zero for a restricted tenant. Gate local serving
// decisions on Deadline.
type MachineTenantServingLease struct {
	TenantID         string
	State            MachineTenantServingState
	Epoch            int64
	AsOf             time.Time
	LeaseExpiresAt   time.Time
	Deadline         time.Time
	ServingChallenge string
}

// GetTenantServingLease uses a key with tenant:serving-lease:read. For each call,
// supply 32 fresh random bytes encoded as unpadded base64url. This method
// validates one response. The caller owns renewal, epoch ordering, failure
// handling, and the independent revocation check.
func (c *MachineUserClient) GetTenantServingLease(ctx context.Context, servingChallenge string) (*MachineTenantServingLease, error) {
	encoding := base64.RawURLEncoding.Strict()
	if len(servingChallenge) != encoding.EncodedLen(machineServingChallengeSize) {
		return nil, errors.New("serving challenge must be 32 bytes encoded as unpadded base64url")
	}
	challenge, err := encoding.DecodeString(servingChallenge)
	if err != nil || len(challenge) != machineServingChallengeSize {
		return nil, errors.New("serving challenge must be 32 bytes encoded as unpadded base64url")
	}

	var response struct {
		TenantID         string                    `json:"tenantId"`
		State            MachineTenantServingState `json:"state"`
		Epoch            string                    `json:"epoch"`
		AsOf             string                    `json:"asOf"`
		LeaseExpiresAt   *string                   `json:"leaseExpiresAt"`
		ServingChallenge string                    `json:"servingChallenge"`
	}
	sentAt := time.Now()
	if err := c.call(ctx, "GetTenantServingLease", struct {
		OrgID            string `json:"orgId"`
		ServingChallenge string `json:"servingChallenge"`
	}{c.orgID, servingChallenge}, &response); err != nil {
		return nil, err
	}
	epoch, err := strconv.ParseInt(response.Epoch, 10, 64)
	asOf, asOfErr := time.Parse(time.RFC3339Nano, response.AsOf)
	if err != nil || epoch < 0 || strconv.FormatInt(epoch, 10) != response.Epoch ||
		response.TenantID != c.orgID || response.ServingChallenge != servingChallenge || asOfErr != nil || asOf.IsZero() {
		return nil, errors.New("Atol returned an invalid serving lease")
	}
	lease := MachineTenantServingLease{
		TenantID:         response.TenantID,
		State:            response.State,
		Epoch:            epoch,
		AsOf:             asOf,
		ServingChallenge: response.ServingChallenge,
	}
	switch response.State {
	case MachineTenantServingStateActive:
		if response.LeaseExpiresAt == nil {
			return nil, errors.New("Atol returned an active serving lease without an expiry")
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, *response.LeaseExpiresAt)
		ttl := expiresAt.Sub(asOf)
		if err != nil || ttl <= 0 || ttl > machineServingLeaseLimit {
			return nil, errors.New("Atol returned an invalid serving lease duration")
		}
		lease.LeaseExpiresAt = expiresAt
		lease.Deadline = sentAt.Add(ttl)
		if !time.Now().Before(lease.Deadline) {
			return nil, errors.New("Atol serving lease expired before receipt")
		}
	case MachineTenantServingStateRestricted:
		if epoch == 0 || response.LeaseExpiresAt != nil {
			return nil, errors.New("Atol returned an invalid restricted serving state")
		}
	default:
		return nil, errors.New("Atol returned an unknown serving state")
	}
	return &lease, nil
}
