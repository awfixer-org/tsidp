// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/util/rands"
)

// Test utilities for creating common test objects.
// These helpers reduce boilerplate and make tests more readable.

// newTestServer creates a minimal IDPServer for testing.
// Use ServerOption functions to customize behavior.
func newTestServer(t *testing.T, opts ...ServerOption) *IDPServer {
	t.Helper()

	s := New(nil, t.TempDir(), false, false, false)
	s.serverURL = "https://idp.test.ts.net"
	s.hostname = "idp.test.ts.net"
	s.loopbackURL = "http://localhost:8080"

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// ServerOption is a function that modifies a test server.
type ServerOption func(*IDPServer)

// WithFunnel enables Funnel mode on the test server.
func WithFunnel() ServerOption {
	return func(s *IDPServer) {
		s.funnel = true
	}
}

// WithSTS enables STS (token exchange) on the test server.
func WithSTS() ServerOption {
	return func(s *IDPServer) {
		s.enableSTS = true
	}
}

// WithLocalTSMode enables local tailscaled mode on the test server.
func WithLocalTSMode() ServerOption {
	return func(s *IDPServer) {
		s.localTSMode = true
	}
}

// WithServerURL sets a custom server URL.
func WithServerURL(url string) ServerOption {
	return func(s *IDPServer) {
		s.serverURL = url
	}
}

// newTestClient creates a FunnelClient for testing.
func newTestClient(t *testing.T, clientID, secret string, redirectURIs ...string) *FunnelClient {
	t.Helper()

	if len(redirectURIs) == 0 {
		redirectURIs = []string{"https://example.com/callback"}
	}

	return &FunnelClient{
		ID:           clientID,
		Secret:       secret,
		RedirectURIs: redirectURIs,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scope:        "openid profile email",
		TokenEndpointAuthMethod: "client_secret_basic",
		CreatedAt:    time.Now(),
	}
}

// newTestUser creates a WhoIsResponse for testing.
// This represents a Tailscale user with valid profile information.
func newTestUser(t *testing.T, email string) *apitype.WhoIsResponse {
	t.Helper()

	return &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			User: 12345,
			Name: "test-node",
		},
		UserProfile: &tailcfg.UserProfile{
			LoginName:   email,
			DisplayName: "Test User",
		},
	}
}

// newTestAuthRequest creates an AuthRequest for testing.
// Use AuthRequestOption functions to customize.
func newTestAuthRequest(t *testing.T, client *FunnelClient, user *apitype.WhoIsResponse, opts ...AuthRequestOption) *AuthRequest {
	t.Helper()

	ar := &AuthRequest{
		ClientID:    client.ID,
		RedirectURI: client.RedirectURIs[0],
		FunnelRP:    client,
		RemoteUser:  user,
		Scopes:      []string{"openid"},
		IssuedAt:    time.Now(),
		ValidTill:   time.Now().Add(5 * time.Minute),
	}

	for _, opt := range opts {
		opt(ar)
	}

	return ar
}

// AuthRequestOption is a function that modifies an AuthRequest.
type AuthRequestOption func(*AuthRequest)

// WithPKCE adds PKCE parameters to an AuthRequest.
func WithPKCE(challenge, method string) AuthRequestOption {
	return func(ar *AuthRequest) {
		ar.CodeChallenge = challenge
		ar.CodeChallengeMethod = method
	}
}

// WithNonce adds a nonce to an AuthRequest.
func WithNonce(nonce string) AuthRequestOption {
	return func(ar *AuthRequest) {
		ar.Nonce = nonce
	}
}

// WithScopes sets the scopes for an AuthRequest.
func WithScopes(scopes ...string) AuthRequestOption {
	return func(ar *AuthRequest) {
		ar.Scopes = scopes
	}
}

// WithResources sets the resource URIs for an AuthRequest.
func WithResources(resources ...string) AuthRequestOption {
	return func(ar *AuthRequest) {
		ar.Resources = resources
	}
}

// WithValidTill sets the expiration time for an AuthRequest.
func WithValidTill(validTill time.Time) AuthRequestOption {
	return func(ar *AuthRequest) {
		ar.ValidTill = validTill
	}
}

// ExpiredAuthRequest makes an AuthRequest expired.
func ExpiredAuthRequest() AuthRequestOption {
	return func(ar *AuthRequest) {
		ar.ValidTill = time.Now().Add(-1 * time.Hour)
	}
}

// addTestClient is a helper that adds a client to a server and returns the client.
func addTestClient(t *testing.T, s *IDPServer, clientID, secret string) *FunnelClient {
	t.Helper()

	client := newTestClient(t, clientID, secret)
	s.mu.Lock()
	s.funnelClients[clientID] = client
	s.mu.Unlock()

	return client
}

// addTestCode adds an authorization code to the server and returns the code string.
func addTestCode(t *testing.T, s *IDPServer, ar *AuthRequest) string {
	t.Helper()

	code := rands.HexString(16) // Use random hex for uniqueness
	s.mu.Lock()
	s.code[code] = ar
	s.mu.Unlock()

	return code
}

// addTestAccessToken adds an access token to the server and returns the token string.
func addTestAccessToken(t *testing.T, s *IDPServer, ar *AuthRequest) string {
	t.Helper()

	token := rands.HexString(16) // Use random hex for uniqueness
	s.mu.Lock()
	s.accessToken[token] = ar
	s.mu.Unlock()

	return token
}

// addTestRefreshToken adds a refresh token to the server and returns the token string.
func addTestRefreshToken(t *testing.T, s *IDPServer, ar *AuthRequest) string {
	t.Helper()

	token := rands.HexString(16) // Use random hex for uniqueness
	s.mu.Lock()
	s.refreshToken[token] = ar
	s.mu.Unlock()

	return token
}
