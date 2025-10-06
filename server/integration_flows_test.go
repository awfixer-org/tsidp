// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
)

// mockLocalClient implements the minimal LocalClient interface needed for testing
type mockLocalClient struct {
	whoIsResponse *apitype.WhoIsResponse
	whoIsError    error
}

func (m *mockLocalClient) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	if m.whoIsError != nil {
		return nil, m.whoIsError
	}
	return m.whoIsResponse, nil
}

// newTestServerWithMockLC creates a test server with a mock LocalClient
func newTestServerWithMockLC(t *testing.T, whoIsResp *apitype.WhoIsResponse, opts ...ServerOption) *IDPServer {
	t.Helper()

	s := &IDPServer{
		serverURL:    "https://idp.example.ts.net",
		code:         make(map[string]*AuthRequest),
		accessToken:  make(map[string]*AuthRequest),
		refreshToken: make(map[string]*AuthRequest),
		funnelClients: make(map[string]*FunnelClient),
		bypassAppCapCheck: true, // Bypass app cap checks for testing
	}

	// Set up mock LocalClient
	mockLC := &mockLocalClient{
		whoIsResponse: whoIsResp,
	}
	// HACK: We need to inject the mock. Since lc is *local.Client,
	// we can't directly assign our mock. For now, we'll work around
	// this limitation by testing at the handler level.
	// TODO: Refactor to use interface for LocalClient
	_ = mockLC

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// TestFullAuthorizationCodeFlow tests the complete happy path OAuth flow
func TestFullAuthorizationCodeFlow(t *testing.T) {
	t.Skip("Skipping until LocalClient can be mocked (see issue #TODO)")

	// This test would verify:
	// 1. User visits /authorize with valid params
	// 2. Server issues authorization code
	// 3. Client exchanges code for tokens
	// 4. Client uses access token for /userinfo
	// 5. All tokens are valid and contain expected claims

	// TODO: Once we can mock lc.WhoIs, implement full flow
	t.Log("Step 1: Authorization request (currently requires mock WhoIs)")
}

// TestAuthCodeFlow_WithPKCE_S256 tests authorization code flow with PKCE S256
func TestAuthCodeFlow_WithPKCE_S256(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "alice@example.com")

	// Create authorization request with PKCE S256
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	ar := newTestAuthRequest(t, client, user,
		WithPKCE(challenge, "S256"),
		WithScopes("openid", "profile", "email"),
		WithNonce("test-nonce-123"))

	code := addTestCode(t, s, ar)

	// Exchange code for tokens with correct verifier
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleAuthorizationCodeGrant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Parse token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	// Verify we got all expected tokens
	if tokenResp.AccessToken == "" {
		t.Error("Expected access_token in response")
	}
	if tokenResp.RefreshToken == "" {
		t.Error("Expected refresh_token in response")
	}
	if tokenResp.IDToken == "" {
		t.Error("Expected id_token in response")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("Expected token_type=Bearer, got %s", tokenResp.TokenType)
	}

	// Verify code was deleted (one-time use)
	s.mu.Lock()
	_, exists := s.code[code]
	s.mu.Unlock()
	if exists {
		t.Error("Authorization code should be deleted after use")
	}

	// Verify access token is stored and valid
	s.mu.Lock()
	storedAR, exists := s.accessToken[tokenResp.AccessToken]
	s.mu.Unlock()
	if !exists {
		t.Fatal("Access token should be stored in server")
	}
	if storedAR.RemoteUser.UserProfile.LoginName != "alice@example.com" {
		t.Errorf("Expected user alice@example.com, got %s", storedAR.RemoteUser.UserProfile.LoginName)
	}

	t.Log("✅ Full auth code flow with PKCE S256 successful")
}

// TestAuthCodeFlow_WithPKCE_Plain tests authorization code flow with PKCE plain
func TestAuthCodeFlow_WithPKCE_Plain(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "bob@example.com")

	// Create authorization request with PKCE plain
	verifier := "my-secure-verifier-that-is-long-enough-for-pkce-validation"

	ar := newTestAuthRequest(t, client, user,
		WithPKCE(verifier, "plain"), // Challenge = verifier for plain method
		WithScopes("openid"))

	code := addTestCode(t, s, ar)

	// Exchange code for tokens
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleAuthorizationCodeGrant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Error("Expected access_token in response")
	}

	t.Log("✅ Full auth code flow with PKCE plain successful")
}

// TestAuthCodeFlow_WithRefresh tests the full flow including token refresh
func TestAuthCodeFlow_WithRefresh(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "charlie@example.com")

	// Step 1: Get initial tokens
	ar := newTestAuthRequest(t, client, user, WithScopes("openid", "profile"))
	code := addTestCode(t, s, ar)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleAuthorizationCodeGrant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Initial token request failed with status %d", w.Code)
	}

	var initialTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &initialTokens); err != nil {
		t.Fatalf("Failed to parse initial tokens: %v", err)
	}

	// Step 2: Use refresh token to get new access token
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", initialTokens.RefreshToken)
	refreshForm.Set("client_id", "test-client")
	refreshForm.Set("client_secret", "test-secret")

	refreshReq := httptest.NewRequest("POST", "/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshW := httptest.NewRecorder()

	s.handleRefreshTokenGrant(refreshW, refreshReq)

	if refreshW.Code != http.StatusOK {
		t.Fatalf("Refresh token request failed with status %d. Body: %s", refreshW.Code, refreshW.Body.String())
	}

	var newTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refreshW.Body.Bytes(), &newTokens); err != nil {
		t.Fatalf("Failed to parse refreshed tokens: %v", err)
	}

	// Verify we got new tokens
	if newTokens.AccessToken == "" {
		t.Error("Expected new access_token")
	}
	if newTokens.RefreshToken == "" {
		t.Error("Expected new refresh_token (rotation)")
	}
	if newTokens.AccessToken == initialTokens.AccessToken {
		t.Error("New access token should be different from initial")
	}

	// Verify old refresh token was deleted (rotation)
	s.mu.Lock()
	_, oldExists := s.refreshToken[initialTokens.RefreshToken]
	s.mu.Unlock()
	if oldExists {
		t.Error("Old refresh token should be deleted after rotation")
	}

	// Verify new refresh token exists
	s.mu.Lock()
	_, newExists := s.refreshToken[newTokens.RefreshToken]
	s.mu.Unlock()
	if !newExists {
		t.Error("New refresh token should be stored")
	}

	t.Log("✅ Full auth code flow with refresh successful")
}

// TestAuthCodeFlow_ErrorPaths tests various error scenarios
func TestAuthCodeFlow_ErrorPaths(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(*IDPServer, *FunnelClient) (code string, form url.Values)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "InvalidCode",
			setup: func(s *IDPServer, client *FunnelClient) (string, url.Values) {
				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", "invalid-code-that-does-not-exist")
				form.Set("redirect_uri", client.RedirectURIs[0])
				form.Set("client_id", "test-client")
				form.Set("client_secret", "test-secret")
				return "", form
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "code not found",
		},
		// Note: Authorization codes don't have explicit expiration checking
		// They rely on ValidTill for background cleanup only
		{
			name: "WrongRedirectURI",
			setup: func(s *IDPServer, client *FunnelClient) (string, url.Values) {
				user := newTestUser(t, "test@example.com")
				ar := newTestAuthRequest(t, client, user)
				code := addTestCode(t, s, ar)

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", code)
				form.Set("redirect_uri", "https://evil.com/callback")
				form.Set("client_id", "test-client")
				form.Set("client_secret", "test-secret")
				return code, form
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "redirect_uri",
		},
		{
			name: "WrongClientSecret",
			setup: func(s *IDPServer, client *FunnelClient) (string, url.Values) {
				user := newTestUser(t, "test@example.com")
				ar := newTestAuthRequest(t, client, user)
				code := addTestCode(t, s, ar)

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", code)
				form.Set("redirect_uri", client.RedirectURIs[0])
				form.Set("client_id", "test-client")
				form.Set("client_secret", "wrong-secret")
				return code, form
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "client authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t)
			client := addTestClient(t, s, "test-client", "test-secret")

			_, form := tt.setup(s, client)

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleAuthorizationCodeGrant(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedError != "" && !strings.Contains(w.Body.String(), tt.expectedError) {
				t.Errorf("Expected error containing %q, got: %s", tt.expectedError, w.Body.String())
			}
		})
	}
}

// TestUserInfoEndpoint tests the /userinfo endpoint with access tokens
func TestUserInfoEndpoint(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "diana@example.com")

	// Create and store access token
	ar := newTestAuthRequest(t, client, user,
		WithScopes("openid", "profile", "email"))
	accessToken := addTestAccessToken(t, s, ar)

	// Request userinfo
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	s.serveUserInfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var userInfo struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &userInfo); err != nil {
		t.Fatalf("Failed to parse userinfo response: %v", err)
	}

	if userInfo.Email != "diana@example.com" {
		t.Errorf("Expected email diana@example.com, got %s", userInfo.Email)
	}
	if userInfo.Sub == "" {
		t.Error("Expected sub claim in userinfo")
	}

	t.Log("✅ UserInfo endpoint successful")
}

// TestIntegrationTokenExpiration tests that expired tokens are properly rejected
func TestIntegrationTokenExpiration(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "expired-user@example.com")

	// Create an expired access token
	ar := newTestAuthRequest(t, client, user, ExpiredAuthRequest())
	expiredToken := addTestAccessToken(t, s, ar)

	// Try to use expired token
	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	w := httptest.NewRecorder()

	s.serveUserInfo(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for expired token, got %d", w.Code)
	}

	// Verify expired token was cleaned up
	s.mu.Lock()
	_, exists := s.accessToken[expiredToken]
	s.mu.Unlock()

	if exists {
		t.Error("Expired token should be removed after detection")
	}

	t.Log("✅ Token expiration handling successful")
}

// TestMultipleScopesFlow tests requesting multiple scopes
func TestMultipleScopesFlow(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "scoped-user@example.com")

	requestedScopes := []string{"openid", "profile", "email"}

	ar := newTestAuthRequest(t, client, user, WithScopes(requestedScopes...))
	code := addTestCode(t, s, ar)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleAuthorizationCodeGrant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	// Verify scopes were stored in the access token's AuthRequest
	s.mu.Lock()
	storedAR, exists := s.accessToken[tokenResp.AccessToken]
	s.mu.Unlock()

	if !exists {
		t.Fatal("Access token should be stored")
	}

	// Verify all requested scopes were granted
	for _, requested := range requestedScopes {
		found := false
		for _, granted := range storedAR.Scopes {
			if requested == granted {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Requested scope %q not found in granted scopes: %v", requested, storedAR.Scopes)
		}
	}

	t.Log("✅ Multiple scopes flow successful")
}

// TestCodeReplayPrevention verifies authorization codes can only be used once
func TestCodeReplayPrevention(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "replay-test@example.com")

	ar := newTestAuthRequest(t, client, user)
	code := addTestCode(t, s, ar)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", client.RedirectURIs[0])
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")

	// First use - should succeed
	req1 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()

	s.handleAuthorizationCodeGrant(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("First token request should succeed, got status %d", w1.Code)
	}

	// Second use - should fail
	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()

	s.handleAuthorizationCodeGrant(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("Code replay should be prevented, got status %d instead of 400", w2.Code)
	}

	t.Log("✅ Code replay prevention successful")
}
