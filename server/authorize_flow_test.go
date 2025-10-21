// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// mockLocalClientForAuthorize implements LocalClient interface for authorize testing
type mockLocalClientForAuthorize struct {
	whoIsResponse *apitype.WhoIsResponse
	whoIsError    error
}

func (m *mockLocalClientForAuthorize) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	if m.whoIsError != nil {
		return nil, m.whoIsError
	}
	return m.whoIsResponse, nil
}

// TestServeAuthorizeSuccess tests successful authorization flow with WhoIs
func TestServeAuthorizeSuccess(t *testing.T) {
	s := newTestServer(t)

	// Set up client
	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Mock WhoIs to return success
	s.lc = &mockLocalClientForAuthorize{
		whoIsResponse: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   123,
				Name: "test-node.example.ts.net",
				User: tailcfg.UserID(456),
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName:   "user@example.com",
				DisplayName: "Test User",
			},
		},
	}

	// Create request
	req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback&state=test-state&nonce=test-nonce&scope=openid+email", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should redirect with code
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected status 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("Expected Location header")
	}

	// Parse redirect URL
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Invalid location URL: %v", err)
	}

	// Verify code is present
	code := u.Query().Get("code")
	if code == "" {
		t.Error("Expected code parameter in redirect URL")
	}

	// Verify state is preserved
	if u.Query().Get("state") != "test-state" {
		t.Errorf("Expected state=test-state, got %s", u.Query().Get("state"))
	}

	// Verify auth request was stored
	s.mu.Lock()
	ar, ok := s.code[code]
	s.mu.Unlock()

	if !ok {
		t.Fatal("Auth request not found in server")
	}

	// Verify auth request fields
	if ar.ClientID != clientID {
		t.Errorf("Expected clientID=%s, got %s", clientID, ar.ClientID)
	}
	if ar.RedirectURI != "https://example.com/callback" {
		t.Errorf("Expected redirectURI=https://example.com/callback, got %s", ar.RedirectURI)
	}
	if ar.Nonce != "test-nonce" {
		t.Errorf("Expected nonce=test-nonce, got %s", ar.Nonce)
	}
	if len(ar.Scopes) != 2 || ar.Scopes[0] != "openid" || ar.Scopes[1] != "email" {
		t.Errorf("Expected scopes=[openid email], got %v", ar.Scopes)
	}
	if ar.RemoteUser == nil {
		t.Error("Expected RemoteUser to be set")
	}
}

// TestServeAuthorizeSuccessWithPKCE tests successful authorization with PKCE
func TestServeAuthorizeSuccessWithPKCE(t *testing.T) {
	s := newTestServer(t)

	// Set up client
	clientID := "pkce-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Mock WhoIs to return success
	s.lc = &mockLocalClientForAuthorize{
		whoIsResponse: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   123,
				Name: "test-node.example.ts.net",
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "user@example.com",
			},
		},
	}

	// Test both PKCE methods
	testCases := []struct {
		name            string
		challengeMethod string
	}{
		{"PKCE with S256", "S256"},
		{"PKCE with plain", "plain"},
		{"PKCE with default plain", ""}, // Empty means default to plain
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+
				"&redirect_uri=https://example.com/callback"+
				"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
				"&code_challenge_method="+tc.challengeMethod, nil)
			req.RemoteAddr = "192.0.2.1:12345"
			w := httptest.NewRecorder()

			s.serveAuthorize(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected status 302, got %d", resp.StatusCode)
				return
			}

			location := resp.Header.Get("Location")
			u, _ := url.Parse(location)
			code := u.Query().Get("code")

			// Verify PKCE was stored
			s.mu.Lock()
			ar, ok := s.code[code]
			s.mu.Unlock()

			if !ok {
				t.Fatal("Auth request not found")
			}

			if ar.CodeChallenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
				t.Errorf("Expected code_challenge to be stored, got %s", ar.CodeChallenge)
			}

			expectedMethod := tc.challengeMethod
			if expectedMethod == "" {
				expectedMethod = "plain"
			}
			if ar.CodeChallengeMethod != expectedMethod {
				t.Errorf("Expected code_challenge_method=%s, got %s", expectedMethod, ar.CodeChallengeMethod)
			}
		})
	}
}

// TestServeAuthorizeWhoIsError tests WhoIs error handling
func TestServeAuthorizeWhoIsError(t *testing.T) {
	s := newTestServer(t)

	// Set up client
	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Mock WhoIs to return error
	s.lc = &mockLocalClientForAuthorize{
		whoIsError: errors.New("WhoIs lookup failed: network error"),
	}

	req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback&state=test", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", resp.StatusCode)
	}

	// Should not redirect on WhoIs error
	location := resp.Header.Get("Location")
	if location != "" {
		t.Error("Should not redirect on WhoIs error")
	}
}

// TestServeAuthorizeInvalidScopeRedirect tests invalid scope error redirect
func TestServeAuthorizeInvalidScopeRedirect(t *testing.T) {
	s := newTestServer(t)

	// Set up client
	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Mock WhoIs to return success
	s.lc = &mockLocalClientForAuthorize{
		whoIsResponse: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   123,
				Name: "test-node.example.ts.net",
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "user@example.com",
			},
		},
	}

	// Request with invalid scope
	req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+
		"&redirect_uri=https://example.com/callback&state=test-state&scope=openid+invalid_scope", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should redirect with error
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect (302), got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("Expected Location header")
	}

	// Parse redirect URL
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Invalid location URL: %v", err)
	}

	// Verify error parameters
	if u.Query().Get("error") != "invalid_scope" {
		t.Errorf("Expected error=invalid_scope, got %s", u.Query().Get("error"))
	}

	if !strings.Contains(u.Query().Get("error_description"), "invalid scope") {
		t.Error("Expected error_description to mention invalid scope")
	}

	// State should be preserved
	if u.Query().Get("state") != "test-state" {
		t.Errorf("Expected state=test-state, got %s", u.Query().Get("state"))
	}

	// Should NOT have a code parameter
	if u.Query().Get("code") != "" {
		t.Error("Should not have code parameter in error redirect")
	}
}

// TestServeAuthorizeUnsupportedPKCEMethodRedirect tests unsupported PKCE method error redirect
func TestServeAuthorizeUnsupportedPKCEMethodRedirect(t *testing.T) {
	s := newTestServer(t)

	// Set up client
	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Mock WhoIs to return success
	s.lc = &mockLocalClientForAuthorize{
		whoIsResponse: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   123,
				Name: "test-node.example.ts.net",
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "user@example.com",
			},
		},
	}

	// Request with unsupported PKCE method
	req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+
		"&redirect_uri=https://example.com/callback&state=test-state"+
		"&code_challenge=test-challenge&code_challenge_method=unsupported", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	s.serveAuthorize(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	// Should redirect with error
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect (302), got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("Expected Location header")
	}

	// Parse redirect URL
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Invalid location URL: %v", err)
	}

	// Verify error parameters
	if u.Query().Get("error") != ecInvalidRequest {
		t.Errorf("Expected error=invalid_request, got %s", u.Query().Get("error"))
	}

	if !strings.Contains(u.Query().Get("error_description"), "code_challenge_method") {
		t.Error("Expected error_description to mention code_challenge_method")
	}

	// State should be preserved
	if u.Query().Get("state") != "test-state" {
		t.Errorf("Expected state=test-state, got %s", u.Query().Get("state"))
	}
}

// TestServeAuthorizeLocalTSMode tests localTSMode X-Forwarded-For handling
func TestServeAuthorizeLocalTSMode(t *testing.T) {
	testCases := []struct {
		name            string
		localTSMode     bool
		remoteAddr      string
		xForwardedFor   string
		expectSuccess   bool
	}{
		{
			name:          "localTSMode with X-Forwarded-For",
			localTSMode:   true,
			remoteAddr:    "127.0.0.1:12345",
			xForwardedFor: "192.0.2.1:8080",
			expectSuccess: true,
		},
		{
			name:          "standard mode ignores X-Forwarded-For",
			localTSMode:   false,
			remoteAddr:    "192.0.2.1:12345",
			xForwardedFor: "10.0.0.1:8080",
			expectSuccess: true,
		},
		{
			name:          "localTSMode without X-Forwarded-For",
			localTSMode:   true,
			remoteAddr:    "192.0.2.1:12345",
			xForwardedFor: "",
			expectSuccess: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			s.localTSMode = tc.localTSMode

			// Set up client
			clientID := "test-client"
			client := addTestClient(t, s, clientID, "test-secret")
			client.RedirectURIs = []string{"https://example.com/callback"}

			// Mock WhoIs to return success
			s.lc = &mockLocalClientForAuthorize{
				whoIsResponse: &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						ID:   123,
						Name: "test-node.example.ts.net",
					},
					UserProfile: &tailcfg.UserProfile{
						LoginName: "user@example.com",
					},
				},
			}

			req := httptest.NewRequest("GET", "/authorize?client_id="+clientID+"&redirect_uri=https://example.com/callback", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}
			w := httptest.NewRecorder()

			s.serveAuthorize(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if tc.expectSuccess {
				if resp.StatusCode != http.StatusFound {
					t.Errorf("Expected status 302, got %d", resp.StatusCode)
				}

				location := resp.Header.Get("Location")
				if location == "" {
					t.Error("Expected Location header")
				} else {
					u, _ := url.Parse(location)
					if u.Query().Get("code") == "" {
						t.Error("Expected code parameter in redirect")
					}
				}
			}
		})
	}
}

// TestServeAuthorizeStatePreservation tests state parameter preservation
func TestServeAuthorizeStatePreservation(t *testing.T) {
	s := newTestServer(t)

	// Set up client
	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Mock WhoIs
	s.lc = &mockLocalClientForAuthorize{
		whoIsResponse: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{ID: 123},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "user@example.com",
			},
		},
	}

	testCases := []struct {
		name  string
		state string
	}{
		{"with state", "random-state-123"},
		{"without state", ""},
		{"state with special chars", "state+with+special%20chars"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL := "/authorize?client_id=" + clientID + "&redirect_uri=https://example.com/callback"
			if tc.state != "" {
				reqURL += "&state=" + url.QueryEscape(tc.state)
			}

			req := httptest.NewRequest("GET", reqURL, nil)
			req.RemoteAddr = "192.0.2.1:12345"
			w := httptest.NewRecorder()

			s.serveAuthorize(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected status 302, got %d", resp.StatusCode)
				return
			}

			location := resp.Header.Get("Location")
			u, _ := url.Parse(location)

			if tc.state != "" {
				if u.Query().Get("state") != tc.state {
					t.Errorf("Expected state=%s, got %s", tc.state, u.Query().Get("state"))
				}
			} else {
				if u.Query().Get("state") != "" {
					t.Errorf("Expected no state parameter, got %s", u.Query().Get("state"))
				}
			}
		})
	}
}
