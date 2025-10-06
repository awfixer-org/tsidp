// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRace_ConcurrentCodeOperations tests concurrent authorization code operations
func TestRace_ConcurrentCodeOperations(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "race-client", "race-secret")

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent code creation and deletion
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "race-user@example.com")
			ar := newTestAuthRequest(t, client, user)

			// Add code
			code := addTestCode(t, s, ar)

			// Immediately try to use it
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", client.RedirectURIs[0])
			form.Set("client_id", "race-client")
			form.Set("client_secret", "race-secret")

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleAuthorizationCodeGrant(w, req)

			// Don't check status - we're testing for races, not correctness
		}(i)
	}

	wg.Wait()
	t.Log("✅ No race conditions detected in concurrent code operations")
}

// TestRace_ConcurrentAccessTokenOperations tests concurrent access token operations
func TestRace_ConcurrentAccessTokenOperations(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "race-client", "race-secret")

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Create shared access tokens
	tokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		user := newTestUser(t, "shared-user@example.com")
		ar := newTestAuthRequest(t, client, user)
		tokens[i] = addTestAccessToken(t, s, ar)
	}

	// Concurrent userinfo requests
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			token := tokens[idx%10]

			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			s.serveUserInfo(w, req)
		}(i)
	}

	wg.Wait()
	t.Log("✅ No race conditions detected in concurrent access token operations")
}

// TestRace_ConcurrentRefreshTokenOperations tests concurrent refresh token operations
func TestRace_ConcurrentRefreshTokenOperations(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "race-client", "race-secret")

	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Each goroutine gets its own refresh token
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "race-user@example.com")
			ar := newTestAuthRequest(t, client, user, WithValidTill(time.Now().Add(24*time.Hour)))
			refreshToken := addTestRefreshToken(t, s, ar)

			// Try to use the refresh token
			form := url.Values{}
			form.Set("grant_type", "refresh_token")
			form.Set("refresh_token", refreshToken)
			form.Set("client_id", "race-client")
			form.Set("client_secret", "race-secret")

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleRefreshTokenGrant(w, req)
		}(i)
	}

	wg.Wait()
	t.Log("✅ No race conditions detected in concurrent refresh token operations")
}

// TestRace_ConcurrentClientOperations tests concurrent client registration/access
func TestRace_ConcurrentClientOperations(t *testing.T) {
	s := newTestServer(t)

	const numGoroutines = 30
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // readers and writers

	// Concurrent client registration
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			clientID := "race-client-" + string(rune('A'+idx))
			client := newTestClient(t, clientID, "secret-"+string(rune('A'+idx)))

			s.mu.Lock()
			s.funnelClients[clientID] = client
			s.mu.Unlock()
		}(i)
	}

	// Concurrent client reading
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			clientID := "race-client-" + string(rune('A'+(idx%10)))

			s.mu.Lock()
			_, _ = s.funnelClients[clientID]
			s.mu.Unlock()
		}(i)
	}

	wg.Wait()
	t.Log("✅ No race conditions detected in concurrent client operations")
}

// TestRace_CleanupDuringOperations tests cleanup running concurrently with token operations
func TestRace_CleanupDuringOperations(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "race-client", "race-secret")

	const numGoroutines = 30
	var wg sync.WaitGroup
	wg.Add(numGoroutines + 1) // operations + cleanup

	// Create some expired and valid tokens
	for i := 0; i < 10; i++ {
		user := newTestUser(t, "cleanup-user@example.com")
		if i%2 == 0 {
			// Expired
			ar := newTestAuthRequest(t, client, user, ExpiredAuthRequest())
			addTestAccessToken(t, s, ar)
			addTestRefreshToken(t, s, ar)
		} else {
			// Valid
			ar := newTestAuthRequest(t, client, user)
			addTestAccessToken(t, s, ar)
			addTestRefreshToken(t, s, ar)
		}
	}

	// Run cleanup in background
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			s.CleanupExpiredTokens()
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Concurrent token operations while cleanup is running
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "concurrent-user@example.com")
			ar := newTestAuthRequest(t, client, user)
			code := addTestCode(t, s, ar)

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", client.RedirectURIs[0])
			form.Set("client_id", "race-client")
			form.Set("client_secret", "race-secret")

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleAuthorizationCodeGrant(w, req)
		}(i)
	}

	wg.Wait()
	t.Log("✅ No race conditions detected during cleanup operations")
}

// TestRace_MixedOperations tests a realistic mix of concurrent operations
func TestRace_MixedOperations(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "mixed-client", "mixed-secret")

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Mix of different operations
	for i := 0; i < numGoroutines; i++ {
		operationType := i % 5

		go func(idx, opType int) {
			defer wg.Done()

			user := newTestUser(t, "mixed-user@example.com")

			switch opType {
			case 0: // Authorization code grant
				ar := newTestAuthRequest(t, client, user)
				code := addTestCode(t, s, ar)

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", code)
				form.Set("redirect_uri", client.RedirectURIs[0])
				form.Set("client_id", "mixed-client")
				form.Set("client_secret", "mixed-secret")

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				s.handleAuthorizationCodeGrant(w, req)

			case 1: // Userinfo request
				ar := newTestAuthRequest(t, client, user)
				token := addTestAccessToken(t, s, ar)

				req := httptest.NewRequest("GET", "/userinfo", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				s.serveUserInfo(w, req)

			case 2: // Refresh token
				ar := newTestAuthRequest(t, client, user, WithValidTill(time.Now().Add(24*time.Hour)))
				refreshToken := addTestRefreshToken(t, s, ar)

				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("refresh_token", refreshToken)
				form.Set("client_id", "mixed-client")
				form.Set("client_secret", "mixed-secret")

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				s.handleRefreshTokenGrant(w, req)

			case 3: // Cleanup
				s.CleanupExpiredTokens()

			case 4: // Client lookup
				s.mu.Lock()
				_, _ = s.funnelClients["mixed-client"]
				s.mu.Unlock()
			}
		}(i, operationType)
	}

	wg.Wait()
	t.Logf("✅ No race conditions detected in mixed operations (%d concurrent ops)", numGoroutines)
}

// TestRace_TokenMapGrowth tests concurrent growth of token maps
func TestRace_TokenMapGrowth(t *testing.T) {
	s := newTestServer(t)
	client := addTestClient(t, s, "growth-client", "growth-secret")

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Rapidly add tokens to all maps
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "growth-user@example.com")
			ar := newTestAuthRequest(t, client, user)

			addTestCode(t, s, ar)
			addTestAccessToken(t, s, ar)
			addTestRefreshToken(t, s, ar)
		}(i)
	}

	wg.Wait()

	// Check that all maps grew correctly
	s.mu.Lock()
	codeCount := len(s.code)
	accessCount := len(s.accessToken)
	refreshCount := len(s.refreshToken)
	s.mu.Unlock()

	if codeCount != numGoroutines {
		t.Errorf("Expected %d codes, got %d", numGoroutines, codeCount)
	}
	if accessCount != numGoroutines {
		t.Errorf("Expected %d access tokens, got %d", numGoroutines, accessCount)
	}
	if refreshCount != numGoroutines {
		t.Errorf("Expected %d refresh tokens, got %d", numGoroutines, refreshCount)
	}

	t.Logf("✅ No race conditions in token map growth (%d codes, %d access, %d refresh)",
		codeCount, accessCount, refreshCount)
}
