// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// TestNewServer tests server initialization with various configurations
func TestNewServer(t *testing.T) {
	testCases := []struct {
		name        string
		lc          LocalClient
		stateDir    string
		funnel      bool
		localTSMode bool
		enableSTS   bool
	}{
		{
			name:        "minimal configuration",
			lc:          &mockLocalClientForAuthorize{},
			stateDir:    "",
			funnel:      false,
			localTSMode: false,
			enableSTS:   false,
		},
		{
			name:        "with funnel enabled",
			lc:          &mockLocalClientForAuthorize{},
			stateDir:    "",
			funnel:      true,
			localTSMode: false,
			enableSTS:   false,
		},
		{
			name:        "with localTSMode enabled",
			lc:          &mockLocalClientForAuthorize{},
			stateDir:    "",
			funnel:      false,
			localTSMode: true,
			enableSTS:   false,
		},
		{
			name:        "with STS enabled",
			lc:          &mockLocalClientForAuthorize{},
			stateDir:    "",
			funnel:      false,
			localTSMode: false,
			enableSTS:   true,
		},
		{
			name:        "all features enabled",
			lc:          &mockLocalClientForAuthorize{},
			stateDir:    t.TempDir(),
			funnel:      true,
			localTSMode: true,
			enableSTS:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.lc, tc.stateDir, tc.funnel, tc.localTSMode, tc.enableSTS)

			if s == nil {
				t.Fatal("Expected server to be created, got nil")
			}

			if s.lc != tc.lc {
				t.Error("LocalClient not set correctly")
			}

			if s.stateDir != tc.stateDir {
				t.Errorf("Expected stateDir=%s, got %s", tc.stateDir, s.stateDir)
			}

			if s.funnel != tc.funnel {
				t.Errorf("Expected funnel=%v, got %v", tc.funnel, s.funnel)
			}

			if s.localTSMode != tc.localTSMode {
				t.Errorf("Expected localTSMode=%v, got %v", tc.localTSMode, s.localTSMode)
			}

			if s.enableSTS != tc.enableSTS {
				t.Errorf("Expected enableSTS=%v, got %v", tc.enableSTS, s.enableSTS)
			}

			// Verify maps are initialized
			if s.code == nil {
				t.Error("code map not initialized")
			}
			if s.accessToken == nil {
				t.Error("accessToken map not initialized")
			}
			if s.refreshToken == nil {
				t.Error("refreshToken map not initialized")
			}
			if s.funnelClients == nil {
				t.Error("funnelClients map not initialized")
			}
		})
	}
}

// TestSetServerURLEdgeCases tests additional server URL edge cases
func TestSetServerURLEdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		hostname    string
		port        int
		expectedURL string
	}{
		{
			name:        "IPv6 address",
			hostname:    "2001:db8::1",
			port:        443,
			expectedURL: "https://2001:db8::1",
		},
		{
			name:        "IPv6 with port",
			hostname:    "2001:db8::1",
			port:        8443,
			expectedURL: "https://2001:db8::1:8443",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := New(nil, "", false, false, false)
			s.SetServerURL(tc.hostname, tc.port)

			if s.hostname != tc.hostname {
				t.Errorf("Expected hostname=%s, got %s", tc.hostname, s.hostname)
			}

			if s.serverURL != tc.expectedURL {
				t.Errorf("Expected serverURL=%s, got %s", tc.expectedURL, s.serverURL)
			}
		})
	}
}

// TestSetRateLimiter tests rate limiter configuration
func TestSetRateLimiter(t *testing.T) {
	s := New(nil, "", false, false, false)

	// Initially nil
	if s.rateLimiter != nil {
		t.Error("Expected rateLimiter to be nil initially")
	}

	// Set rate limiter
	config := RateLimitConfig{
		TokensPerSecond: 10,
		BurstSize:       20,
		BypassLocalhost: true,
	}
	s.SetRateLimiter(config)

	if s.rateLimiter == nil {
		t.Error("Expected rateLimiter to be set")
	}
}

// TestOIDCPrivateKeyGeneration tests RSA key generation and persistence
func TestOIDCPrivateKeyGeneration(t *testing.T) {
	tempDir := t.TempDir()
	s := New(nil, tempDir, false, false, false)

	// First call should generate a new key
	key1, err := s.oidcPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if key1 == nil {
		t.Fatal("Expected key to be generated")
	}

	if key1.Key == nil {
		t.Error("Expected RSA key to be set")
	}

	if key1.Kid == 0 {
		t.Error("Expected Kid to be non-zero")
	}

	// Verify key was persisted
	keyPath := filepath.Join(tempDir, "oidc-key.json")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Expected key file to be created")
	}

	// Second call should return the same key (lazy loading)
	key2, err := s.oidcPrivateKey()
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	if key1.Kid != key2.Kid {
		t.Error("Expected same key to be returned")
	}
}

// TestOIDCPrivateKeyLoadExisting tests loading an existing key
func TestOIDCPrivateKeyLoadExisting(t *testing.T) {
	tempDir := t.TempDir()

	// Create server and generate initial key
	s1 := New(nil, tempDir, false, false, false)
	key1, err := s1.oidcPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create new server instance (simulating restart)
	s2 := New(nil, tempDir, false, false, false)
	key2, err := s2.oidcPrivateKey()
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Should load the same key
	if key1.Kid != key2.Kid {
		t.Error("Expected same key ID after reload")
	}
}

// TestOIDCPrivateKeyNoStateDir tests key generation without state directory
func TestOIDCPrivateKeyNoStateDir(t *testing.T) {
	// Create server without state directory
	s := New(nil, "", false, false, false)

	// Should still generate a key (in current directory)
	key, err := s.oidcPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if key == nil {
		t.Fatal("Expected key to be generated")
	}

	// Clean up key file in current directory
	defer os.Remove("oidc-key.json")
}

// TestOIDCSigner tests OIDC signer creation
func TestOIDCSigner(t *testing.T) {
	tempDir := t.TempDir()
	s := New(nil, tempDir, false, false, false)

	signer, err := s.oidcSigner()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer == nil {
		t.Error("Expected signer to be created")
	}

	// Second call should return cached signer
	signer2, err := s.oidcSigner()
	if err != nil {
		t.Fatalf("Failed to get signer: %v", err)
	}

	if signer != signer2 {
		t.Error("Expected same signer to be returned (lazy loading)")
	}
}

// TestRealishEmailEdgeCases tests additional email formatting edge cases
func TestRealishEmailEdgeCases(t *testing.T) {
	s := New(nil, "", false, false, false)
	s.hostname = "idp.example.ts.net"

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "github subdomain",
			input:    "octocat@github",
			expected: "octocat@github.idp.example.ts.net",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := s.realishEmail(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestCleanupExpiredTokensConcurrent tests concurrent token cleanup
func TestCleanupExpiredTokensConcurrent(t *testing.T) {
	s := newTestServer(t)

	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	user := newTestUser(t, "test@example.com")

	// Add some tokens
	ar := newTestAuthRequest(t, client, user)
	code := addTestCode(t, s, ar)
	token := addTestAccessToken(t, s, ar)

	// Expire them
	pastTime := time.Now().Add(-time.Hour)
	s.mu.Lock()
	s.code[code].ValidTill = pastTime
	s.accessToken[token].ValidTill = pastTime
	s.mu.Unlock()

	// Run cleanup concurrently (test thread safety)
	done := make(chan bool, 2)
	go func() {
		s.CleanupExpiredTokens()
		done <- true
	}()
	go func() {
		s.CleanupExpiredTokens()
		done <- true
	}()

	<-done
	<-done

	// Verify tokens were removed
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.code[code]; exists {
		t.Error("Expired code should be removed")
	}
	if _, exists := s.accessToken[token]; exists {
		t.Error("Expired access token should be removed")
	}
}

// TestCleanupExpiredTokensWithZeroExpiry tests cleanup with tokens that have zero expiry
func TestCleanupExpiredTokensWithZeroExpiry(t *testing.T) {
	s := newTestServer(t)

	clientID := "test-client"
	addTestClient(t, s, clientID, "test-secret")

	// Add refresh token with zero expiry (never expires)
	refreshToken := "never-expires"
	s.mu.Lock()
	s.refreshToken[refreshToken] = &AuthRequest{
		ClientID:  clientID,
		ValidTill: time.Time{}, // Zero time - never expires
	}
	s.mu.Unlock()

	// Run cleanup
	s.CleanupExpiredTokens()

	// Verify token was not removed
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.refreshToken[refreshToken]; !exists {
		t.Error("Refresh token with zero expiry should not be removed")
	}
}

// TestNewMux tests HTTP mux creation
func TestNewMux(t *testing.T) {
	s := newTestServer(t)

	mux := s.newMux()
	if mux == nil {
		t.Fatal("Expected mux to be created")
	}

	// Verify mux is callable (basic smoke test)
	// We don't test specific routes here as those are tested in integration tests
}

// TestServerHTTPHandler tests ServeHTTP implementation
func TestServerHTTPHandler(t *testing.T) {
	s := newTestServer(t)

	// Set up minimal configuration
	s.SetServerURL("idp.example.ts.net", 443)

	// Set up mock LocalClient for authorize endpoint
	s.lc = &mockLocalClientForAuthorize{
		whoIsResponse: &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				ID:   123,
				Name: "test-node.example.ts.net",
			},
			UserProfile: &tailcfg.UserProfile{
				LoginName: "test@example.com",
			},
		},
	}

	// Add a test client
	clientID := "test-client"
	client := addTestClient(t, s, clientID, "test-secret")
	client.RedirectURIs = []string{"https://example.com/callback"}

	// Test that ServeHTTP delegates to the mux
	testCases := []struct {
		path         string
		expectStatus int
	}{
		{
			path:         "/.well-known/openid-configuration",
			expectStatus: 200, // Should return OIDC configuration
		},
		{
			path:         "/.well-known/jwks.json",
			expectStatus: 200, // Should return JWKS
		},
		{
			path:         "/authorize?client_id=" + clientID + "&redirect_uri=https://example.com/callback",
			expectStatus: 302, // Should redirect with code
		},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.RemoteAddr = "192.0.2.1:12345"
			w := httptest.NewRecorder()

			s.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectStatus {
				t.Errorf("Expected status %d, got %d for path %s", tc.expectStatus, resp.StatusCode, tc.path)
			}
		})
	}
}

// TestGenRSAKey tests RSA key generation
func TestGenRSAKey(t *testing.T) {
	testCases := []struct {
		name string
		bits int
	}{
		{"2048 bits", 2048},
		{"4096 bits", 4096},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kid, key, err := genRSAKey(tc.bits)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			if kid == 0 {
				t.Error("Expected non-zero kid")
			}

			if key == nil {
				t.Fatal("Expected key to be generated")
			}

			if key.N.BitLen() != tc.bits {
				t.Errorf("Expected %d bit key, got %d bits", tc.bits, key.N.BitLen())
			}
		})
	}
}

// TestSigningKeyMarshalUnmarshal tests signing key serialization
func TestSigningKeyMarshalUnmarshal(t *testing.T) {
	// Generate a test key
	kid, key, err := genRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	sk := &signingKey{
		Kid: kid,
		Key: key,
	}

	// Marshal to JSON
	data, err := sk.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty marshaled data")
	}

	// Unmarshal from JSON
	sk2 := &signingKey{}
	err = sk2.UnmarshalJSON(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal key: %v", err)
	}

	if sk2.Kid != sk.Kid {
		t.Errorf("Expected Kid=%d, got %d", sk.Kid, sk2.Kid)
	}

	if sk2.Key == nil {
		t.Fatal("Expected key to be unmarshaled")
	}

	// Verify keys are equivalent
	if sk.Key.N.Cmp(sk2.Key.N) != 0 {
		t.Error("Expected same key modulus")
	}
}

// TestSigningKeyMarshalNilKey tests marshaling with nil key
func TestSigningKeyMarshalNilKey(t *testing.T) {
	sk := &signingKey{
		Kid: 123,
		Key: nil,
	}

	_, err := sk.MarshalJSON()
	if err == nil {
		t.Error("Expected error when marshaling nil key")
	}

	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("Expected error message to mention nil, got: %v", err)
	}
}

// TestSigningKeyUnmarshalInvalidJSON tests unmarshaling invalid JSON
func TestSigningKeyUnmarshalInvalidJSON(t *testing.T) {
	testCases := []struct {
		name string
		data string
	}{
		{
			name: "invalid JSON",
			data: `{invalid json}`,
		},
		{
			name: "invalid PEM",
			data: `{"kid": 123, "key": "not-a-pem-key"}`,
		},
		{
			name: "empty key",
			data: `{"kid": 123, "key": ""}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sk := &signingKey{}
			err := sk.UnmarshalJSON([]byte(tc.data))
			if err == nil {
				t.Error("Expected error when unmarshaling invalid data")
			}
		})
	}
}

// TestWriteHTTPError tests error response formatting
func TestWriteHTTPError(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		errorCode    string
		description  string
		acceptHeader string
		expectJSON   bool
	}{
		{
			name:         "JSON response",
			statusCode:   400,
			errorCode:    ecInvalidRequest,
			description:  "Invalid request",
			acceptHeader: "application/json",
			expectJSON:   true,
		},
		{
			name:         "plain text response",
			statusCode:   401,
			errorCode:    ecAccessDenied,
			description:  "Access denied",
			acceptHeader: "text/html",
			expectJSON:   false,
		},
		{
			name:         "no accept header defaults to text",
			statusCode:   403,
			errorCode:    ecInvalidClient,
			description:  "Invalid client",
			acceptHeader: "",
			expectJSON:   false,
		},
		{
			name:         "internal server error",
			statusCode:   500,
			errorCode:    ecServerError,
			description:  "Server error",
			acceptHeader: "application/json",
			expectJSON:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tc.acceptHeader != "" {
				req.Header.Set("Accept", tc.acceptHeader)
			}
			w := httptest.NewRecorder()

			writeHTTPError(w, req, tc.statusCode, tc.errorCode, tc.description, nil)

			resp := w.Result()
			defer resp.Body.Close()

			if resp.StatusCode != tc.statusCode {
				t.Errorf("Expected status %d, got %d", tc.statusCode, resp.StatusCode)
			}

			contentType := resp.Header.Get("Content-Type")
			if tc.expectJSON {
				if !strings.Contains(contentType, "application/json") {
					t.Errorf("Expected JSON content type, got %s", contentType)
				}
			} else {
				if !strings.Contains(contentType, "text/plain") {
					t.Errorf("Expected text/plain content type, got %s", contentType)
				}
			}

			// Verify Cache-Control headers are set
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Error("Expected Cache-Control: no-store header")
			}
			if resp.Header.Get("Pragma") != "no-cache" {
				t.Error("Expected Pragma: no-cache header")
			}
		})
	}
}
