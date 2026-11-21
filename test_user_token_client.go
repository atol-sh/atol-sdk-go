package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const TestUserGrantType = "urn:atol:params:oauth:grant-type:test-user"

// TestUserTokenClient requests short-lived access tokens from an isolated test
// tenant. The confidential client credential is distinct from an Atol API key.
type TestUserTokenClient struct {
	issuer       string
	clientID     string
	clientSecret string
	http         *http.Client
}

type TestUserToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

func NewTestUserTokenClient(issuer, clientID, clientSecret string, httpClient *http.Client) (*TestUserTokenClient, error) {
	baseURL, err := serviceBaseURL(issuer)
	if err != nil {
		return nil, err
	}
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("test-user token client requires confidential client credentials")
	}
	return &TestUserTokenClient{issuer: baseURL, clientID: clientID,
		clientSecret: clientSecret, http: serviceHTTPClient(httpClient)}, nil
}

// Token creates an access-only token for an existing test-marked Atol user.
// Callers must use the registered audience and a test tenant issuer.
func (c *TestUserTokenClient) Token(ctx context.Context, userID, audience string, scopes []string) (*TestUserToken, error) {
	if userID == "" || audience == "" {
		return nil, errors.New("test-user token requires user ID and audience")
	}
	for _, scope := range scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") || scope == "openid" || scope == "offline_access" {
			return nil, errors.New("invalid test-user token scope")
		}
	}
	form := url.Values{
		"grant_type":    {TestUserGrantType},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"subject":       {userID},
		"audience":      {audience},
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	var response struct {
		TestUserToken
		RefreshToken json.RawMessage `json:"refresh_token"`
		IDToken      json.RawMessage `json:"id_token"`
	}
	if err := serviceRequest(ctx, c.http, c.issuer+"/auth/token", "application/x-www-form-urlencoded", []byte(form.Encode()), &response); err != nil {
		return nil, err
	}
	if len(response.RefreshToken) != 0 || len(response.IDToken) != 0 ||
		response.AccessToken == "" || !strings.EqualFold(response.TokenType, "Bearer") || response.ExpiresIn <= 0 {
		return nil, errors.New("Atol returned an invalid test-user token response")
	}
	return &response.TestUserToken, nil
}
