package sdk

import (
	"errors"
	"testing"
	"time"

	atolidentity "atol.sh/sdk-go/identity"
)

func TestCheckTokenSessionRequiresFreshCRLForTestTokens(t *testing.T) {
	claims := &atolidentity.AtolClaims{TestUser: true, AuthMethod: "test"}
	for _, tc := range []struct {
		name      string
		validator *SessionValidator
		sessionID string
		wantError bool
	}{
		{"no validator", nil, "active", true},
		{"never fetched", &SessionValidator{pollInterval: 30 * time.Second}, "active", true},
		{"stale", &SessionValidator{pollInterval: 30 * time.Second, lastSuccessAt: time.Now().Add(-2 * time.Minute)}, "active", true},
		{"future timestamp", &SessionValidator{pollInterval: 30 * time.Second, lastSuccessAt: time.Now().Add(time.Minute)}, "active", true},
		{"refresh failed", &SessionValidator{pollInterval: 30 * time.Second, lastSuccessAt: time.Now(), lastRefreshErr: errors.New("offline")}, "active", true},
		{"revoked", &SessionValidator{pollInterval: 30 * time.Second, lastSuccessAt: time.Now(), revoked: map[string]struct{}{"active": {}}}, "active", true},
		{"missing jti", &SessionValidator{pollInterval: 30 * time.Second, lastSuccessAt: time.Now()}, "", true},
		{"active", &SessionValidator{pollInterval: 30 * time.Second, lastSuccessAt: time.Now()}, "active", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := &Atol{sessionValidator: tc.validator}
			err := engine.CheckTokenSession(claims, tc.sessionID)
			if (err != nil) != tc.wantError {
				t.Errorf("CheckTokenSession() error = %v, wantError %v", err, tc.wantError)
			}
		})
	}
}

func TestCheckTokenSessionChecksOrdinaryRevocationsWhenConfigured(t *testing.T) {
	ordinary := &atolidentity.AtolClaims{AuthMethod: "password"}
	if err := (&Atol{}).CheckTokenSession(ordinary, "session"); err != nil {
		t.Fatalf("ordinary token without CRL error = %v, want nil", err)
	}
	engine := &Atol{sessionValidator: &SessionValidator{revoked: map[string]struct{}{"session": {}}}}
	if err := engine.CheckTokenSession(ordinary, "session"); !errors.Is(err, ErrTokenSessionRejected) {
		t.Errorf("revoked ordinary token error = %v, want ErrTokenSessionRejected", err)
	}
}
