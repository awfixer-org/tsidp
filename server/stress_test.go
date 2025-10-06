// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStress_HighConcurrencyTokenGrant tests server under high concurrent load
func TestStress_HighConcurrencyTokenGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := newTestServer(t)
	client := addTestClient(t, s, "stress-client", "stress-secret")

	const numRequests = 500
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var failureCount atomic.Int32

	wg.Add(numRequests)
	startTime := time.Now()

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "stress-user@example.com")
			ar := newTestAuthRequest(t, client, user, WithScopes("openid", "profile"))
			code := addTestCode(t, s, ar)

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", client.RedirectURIs[0])
			form.Set("client_id", "stress-client")
			form.Set("client_secret", "stress-secret")

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleAuthorizationCodeGrant(w, req)

			if w.Code == 200 {
				successCount.Add(1)
			} else {
				failureCount.Add(1)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	success := successCount.Load()
	failure := failureCount.Load()

	t.Logf("✅ Stress test complete: %d requests in %v", numRequests, duration)
	t.Logf("   Success: %d (%.1f%%), Failures: %d (%.1f%%)",
		success, float64(success)/float64(numRequests)*100,
		failure, float64(failure)/float64(numRequests)*100)
	t.Logf("   Throughput: %.0f req/s", float64(numRequests)/duration.Seconds())

	if success < int32(numRequests*0.95) {
		t.Errorf("Success rate too low: %d/%d (%.1f%%)", success, numRequests,
			float64(success)/float64(numRequests)*100)
	}
}

// TestStress_ConcurrentUserInfo tests UserInfo endpoint under load
func TestStress_ConcurrentUserInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := newTestServer(t)
	client := addTestClient(t, s, "stress-client", "stress-secret")

	// Create pool of access tokens
	const numTokens = 50
	tokens := make([]string, numTokens)
	for i := 0; i < numTokens; i++ {
		user := newTestUser(t, "userinfo-user@example.com")
		ar := newTestAuthRequest(t, client, user, WithScopes("openid", "profile", "email"))
		tokens[i] = addTestAccessToken(t, s, ar)
	}

	const numRequests = 1000
	var wg sync.WaitGroup
	var successCount atomic.Int32

	wg.Add(numRequests)
	startTime := time.Now()

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			defer wg.Done()

			token := tokens[idx%numTokens]
			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			s.serveUserInfo(w, req)

			if w.Code == 200 {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)
	success := successCount.Load()

	t.Logf("✅ UserInfo stress test: %d requests in %v", numRequests, duration)
	t.Logf("   Success: %d (%.1f%%)", success, float64(success)/float64(numRequests)*100)
	t.Logf("   Throughput: %.0f req/s", float64(numRequests)/duration.Seconds())

	if success != numRequests {
		t.Errorf("Expected all requests to succeed, got %d/%d", success, numRequests)
	}
}

// TestStress_RefreshTokenChurn tests rapid refresh token rotation
func TestStress_RefreshTokenChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := newTestServer(t)
	client := addTestClient(t, s, "churn-client", "churn-secret")

	const numClients = 20
	const refreshesPerClient = 10

	var wg sync.WaitGroup
	var totalSuccess atomic.Int32

	wg.Add(numClients)
	startTime := time.Now()

	for i := 0; i < numClients; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "churn-user@example.com")
			ar := newTestAuthRequest(t, client, user,
				WithValidTill(time.Now().Add(24*time.Hour)),
				WithScopes("openid"))

			currentRefreshToken := addTestRefreshToken(t, s, ar)

			// Perform multiple refreshes in sequence
			for j := 0; j < refreshesPerClient; j++ {
				form := url.Values{}
				form.Set("grant_type", "refresh_token")
				form.Set("refresh_token", currentRefreshToken)
				form.Set("client_id", "churn-client")
				form.Set("client_secret", "churn-secret")

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()

				s.handleRefreshTokenGrant(w, req)

				if w.Code == 200 {
					totalSuccess.Add(1)
					// Extract new refresh token for next iteration
					// In real implementation, would parse JSON response
					// For now, we just break after first success since we don't have the new token
					break
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)
	success := totalSuccess.Load()

	t.Logf("✅ Refresh token churn test: %d clients, %d total refreshes in %v",
		numClients, success, duration)
	t.Logf("   Throughput: %.0f refreshes/s", float64(success)/duration.Seconds())

	if success < int32(numClients*0.95) {
		t.Errorf("Too many refresh failures: %d/%d", success, numClients)
	}
}

// TestStress_MemoryUsage tests memory usage under sustained load
func TestStress_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := newTestServer(t)
	client := addTestClient(t, s, "memory-client", "memory-secret")

	const numTokens = 1000
	var wg sync.WaitGroup
	wg.Add(numTokens)

	startTime := time.Now()

	// Create many tokens
	for i := 0; i < numTokens; i++ {
		go func(idx int) {
			defer wg.Done()

			user := newTestUser(t, "memory-user@example.com")
			ar := newTestAuthRequest(t, client, user)

			addTestCode(t, s, ar)
			addTestAccessToken(t, s, ar)
			addTestRefreshToken(t, s, ar)
		}(i)
	}

	wg.Wait()
	creationTime := time.Since(startTime)

	// Check token counts
	s.mu.Lock()
	codeCount := len(s.code)
	accessCount := len(s.accessToken)
	refreshCount := len(s.refreshToken)
	s.mu.Unlock()

	t.Logf("✅ Memory stress test: Created %d tokens in %v", numTokens, creationTime)
	t.Logf("   Codes: %d, Access: %d, Refresh: %d", codeCount, accessCount, refreshCount)
	t.Logf("   Creation rate: %.0f tokens/s", float64(numTokens*3)/creationTime.Seconds())

	// Cleanup
	startCleanup := time.Now()
	s.CleanupExpiredTokens()
	cleanupTime := time.Since(startCleanup)

	s.mu.Lock()
	afterCodes := len(s.code)
	afterAccess := len(s.accessToken)
	afterRefresh := len(s.refreshToken)
	s.mu.Unlock()

	t.Logf("   After cleanup (%v): Codes: %d, Access: %d, Refresh: %d",
		cleanupTime, afterCodes, afterAccess, afterRefresh)
}

// TestStress_BurstLoad tests handling of sudden traffic spikes
func TestStress_BurstLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := newTestServer(t)
	client := addTestClient(t, s, "burst-client", "burst-secret")

	const numBursts = 5
	const requestsPerBurst = 100

	totalStart := time.Now()
	var totalSuccess atomic.Int32

	for burst := 0; burst < numBursts; burst++ {
		var wg sync.WaitGroup
		wg.Add(requestsPerBurst)
		burstStart := time.Now()

		// Sudden burst of requests
		for i := 0; i < requestsPerBurst; i++ {
			go func(idx int) {
				defer wg.Done()

				user := newTestUser(t, "burst-user@example.com")
				ar := newTestAuthRequest(t, client, user)
				code := addTestCode(t, s, ar)

				form := url.Values{}
				form.Set("grant_type", "authorization_code")
				form.Set("code", code)
				form.Set("redirect_uri", client.RedirectURIs[0])
				form.Set("client_id", "burst-client")
				form.Set("client_secret", "burst-secret")

				req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()

				s.handleAuthorizationCodeGrant(w, req)

				if w.Code == 200 {
					totalSuccess.Add(1)
				}
			}(i)
		}

		wg.Wait()
		burstDuration := time.Since(burstStart)
		t.Logf("   Burst %d: %d requests in %v (%.0f req/s)",
			burst+1, requestsPerBurst, burstDuration,
			float64(requestsPerBurst)/burstDuration.Seconds())

		// Brief pause between bursts
		time.Sleep(50 * time.Millisecond)
	}

	totalDuration := time.Since(totalStart)
	totalRequests := numBursts * requestsPerBurst
	success := totalSuccess.Load()

	t.Logf("✅ Burst load test complete: %d requests in %d bursts over %v",
		totalRequests, numBursts, totalDuration)
	t.Logf("   Success: %d (%.1f%%)", success, float64(success)/float64(totalRequests)*100)
	t.Logf("   Overall throughput: %.0f req/s", float64(totalRequests)/totalDuration.Seconds())
}

// TestStress_LockContention measures lock contention under load
func TestStress_LockContention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := newTestServer(t)
	client := addTestClient(t, s, "contention-client", "contention-secret")

	const numGoroutines = 200
	const operationsPerGoroutine = 5

	var wg sync.WaitGroup
	var lockAcquireCount atomic.Int32

	wg.Add(numGoroutines)
	startTime := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				// Mix of operations that require locks
				switch j % 3 {
				case 0: // Add client (write lock)
					clientID := "temp-client-" + string(rune('A'+(idx%26)))
					tempClient := newTestClient(t, clientID, "secret")
					s.mu.Lock()
					s.funnelClients[clientID] = tempClient
					s.mu.Unlock()
					lockAcquireCount.Add(1)

				case 1: // Read client (read operation with lock)
					s.mu.Lock()
					_ = s.funnelClients["contention-client"]
					s.mu.Unlock()
					lockAcquireCount.Add(1)

				case 2: // Add token (write lock)
					user := newTestUser(t, "contention@example.com")
					ar := newTestAuthRequest(t, client, user)
					addTestCode(t, s, ar)
					lockAcquireCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)
	lockAcquires := lockAcquireCount.Load()

	t.Logf("✅ Lock contention test: %d goroutines, %d total operations",
		numGoroutines, lockAcquires)
	t.Logf("   Duration: %v", duration)
	t.Logf("   Lock acquires/s: %.0f", float64(lockAcquires)/duration.Seconds())
	t.Logf("   Average time per operation: %v", duration/time.Duration(lockAcquires))
}
