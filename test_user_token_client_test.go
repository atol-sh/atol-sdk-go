package sdk_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "atol.sh/sdk-go"
	"atol.sh/sdk-go/atoltest"
)

func TestTestUserTokenClientAccessOnly(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/token" || r.Method != http.MethodPost {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Atol-Org-Id"); got != "" {
			t.Errorf("token request organization header = %q, want empty", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		for key, want := range map[string]string{
			"grant_type": sdk.TestUserGrantType, "client_id": "test-client",
			"client_secret": "test-secret", "subject": "user-1",
			"audience": "game-test", "scope": "profile email",
		} {
			if got := r.PostForm.Get(key); got != want {
				t.Errorf("form %s = %q, want %q", key, got, want)
			}
		}
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":300}`))
	}))
	t.Cleanup(server.Close)
	client, err := sdk.NewTestUserTokenClient(server.URL, "test-client", "test-secret", nil)
	if err != nil {
		t.Fatalf("new token client: %v", err)
	}
	token, err := client.Token(context.Background(), "user-1", "game-test", []string{"profile", "email"})
	if err != nil || token.AccessToken != "access" || token.ExpiresIn != 300 {
		t.Fatalf("token = %+v, %v", token, err)
	}
}

func TestTestUserTokenClientRejectsUnexpectedRefresh(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":300,"refresh_token":"unexpected"}`))
	}))
	t.Cleanup(server.Close)
	client, err := sdk.NewTestUserTokenClient(server.URL, "c", "s", nil)
	if err != nil {
		t.Fatalf("new token client: %v", err)
	}
	if _, err := client.Token(context.Background(), "u", "a", nil); err == nil {
		t.Fatal("refresh token response accepted")
	}
}

func TestTestUserTokenClientDoesNotForwardSecretOnRedirect(t *testing.T) {
	t.Parallel()
	forwarded := false
	attacker := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		forwarded = true
	}))
	t.Cleanup(attacker.Close)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", attacker.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(issuer.Close)
	client, err := sdk.NewTestUserTokenClient(issuer.URL, "c", "s", nil)
	if err != nil {
		t.Fatalf("new token client: %v", err)
	}
	if _, err := client.Token(context.Background(), "u", "a", nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if forwarded {
		t.Fatal("client secret was forwarded to redirect target")
	}
}

func TestTokenValidatorRejectsTestTokensByDefault(t *testing.T) {
	t.Parallel()
	factory := atoltest.NewTokenFactory(t)
	validator := sdk.NewTokenValidator(factory.JWKSUrl(), factory.Issuer(), "game")
	for _, options := range [][]atoltest.TokenOption{
		{atoltest.WithTestUser(), atoltest.WithAudience("game")},
		{atoltest.WithAuthMethod("test"), atoltest.WithAudience("game")},
	} {
		_, _, _, _, err := validator.ValidateToken(context.Background(), factory.MintToken(options...))
		if !errors.Is(err, sdk.ErrTestTokenRejected) {
			t.Errorf("test token error = %v, want ErrTestTokenRejected", err)
		}
	}
	allow := sdk.NewTokenValidator(factory.JWKSUrl(), factory.Issuer(), "game",
		sdk.WithAllowTestTokens(), sdk.WithExpectedOrgID("tenant-a"))
	_, _, claims, _, err := allow.ValidateToken(context.Background(), factory.MintToken(
		atoltest.WithTestUser(), atoltest.WithAudience("game"), atoltest.WithOrgID("tenant-a")))
	if err != nil || !claims.TestUser {
		t.Fatalf("allowed test token claims = %+v, %v", claims, err)
	}
	_, _, _, _, err = allow.ValidateToken(context.Background(), factory.MintToken(
		atoltest.WithTestUser(), atoltest.WithAudience("other"), atoltest.WithOrgID("tenant-a")))
	if err == nil || strings.Contains(err.Error(), "ErrTestTokenRejected") {
		t.Fatalf("wrong audience error = %v, want audience denial", err)
	}
	noAudience := sdk.NewTokenValidator(factory.JWKSUrl(), factory.Issuer(), "", sdk.WithAllowTestTokens())
	_, _, _, _, err = noAudience.ValidateToken(context.Background(), factory.MintToken(atoltest.WithTestUser()))
	if !errors.Is(err, sdk.ErrTestTokenRejected) {
		t.Fatalf("test token without configured audience error = %v", err)
	}
	for _, tc := range []struct {
		name      string
		validator *sdk.TokenValidator
		orgID     string
	}{
		{"missing expected tenant", sdk.NewTokenValidator(factory.JWKSUrl(), factory.Issuer(), "game", sdk.WithAllowTestTokens()), "tenant-a"},
		{"wrong tenant", allow, "tenant-b"},
		{"missing claim", allow, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := tc.validator.ValidateToken(context.Background(), factory.MintToken(
				atoltest.WithTestUser(), atoltest.WithAudience("game"), atoltest.WithOrgID(tc.orgID)))
			if !errors.Is(err, sdk.ErrTestTokenRejected) {
				t.Errorf("tenant %q error = %v, want ErrTestTokenRejected", tc.orgID, err)
			}
		})
	}
}

func TestAtolNewPinsTestTokensToConfiguredTenant(t *testing.T) {
	t.Parallel()
	if _, err := sdk.New(sdk.Config{AllowTestTokens: true}); err == nil {
		t.Fatal("test-token SDK without StoreID was accepted")
	}
	factory := atoltest.NewTokenFactory(t)
	engine, err := sdk.New(sdk.Config{
		StoreID: "tenant-a", Issuer: factory.Issuer(), JWKSUrl: factory.JWKSUrl(),
		Audience: "game", AllowTestTokens: true,
	})
	if err != nil {
		t.Fatalf("sdk.New: %v", err)
	}
	t.Cleanup(engine.Close)
	for _, tc := range []struct {
		orgID     string
		wantError bool
	}{
		{"tenant-a", false},
		{"tenant-b", true},
		{"", true},
	} {
		_, _, _, _, err := engine.Validator().ValidateToken(context.Background(), factory.MintToken(
			atoltest.WithTestUser(), atoltest.WithOrgID(tc.orgID), atoltest.WithAudience("game")))
		if (err != nil) != tc.wantError {
			t.Errorf("org %q validation error = %v, wantError %v", tc.orgID, err, tc.wantError)
		}
	}
}

func TestTokenValidatorRejectsExpiredTestTokensWithoutLeeway(t *testing.T) {
	t.Parallel()
	factory := atoltest.NewTokenFactory(t)
	validator := sdk.NewTokenValidator(factory.JWKSUrl(), factory.Issuer(), "game",
		sdk.WithAllowTestTokens(), sdk.WithExpectedOrgID("tenant-a"))
	for _, tc := range []struct {
		name    string
		options []atoltest.TokenOption
	}{
		{"test marker", []atoltest.TokenOption{atoltest.WithTestUser()}},
		{"test auth method", []atoltest.TokenOption{atoltest.WithAuthMethod("test")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := append([]atoltest.TokenOption{
				atoltest.WithOrgID("tenant-a"), atoltest.WithAudience("game"),
				atoltest.WithExpiry(-5 * time.Second),
			}, tc.options...)
			_, _, _, _, err := validator.ValidateToken(context.Background(), factory.MintToken(options...))
			if !errors.Is(err, sdk.ErrTestTokenRejected) {
				t.Errorf("expired test token error = %v, want ErrTestTokenRejected", err)
			}
		})
	}
}
