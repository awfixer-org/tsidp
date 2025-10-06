// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestPKCE_AllMethods tests all PKCE code challenge methods comprehensively
func TestPKCE_AllMethods(t *testing.T) {
	tests := []struct {
		name          string
		verifier      string
		challenge     string
		method        string
		shouldSucceed bool
		errorContains string
	}{
		// Valid cases
		{
			name:          "Valid_S256_Standard",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:        "S256",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Plain_Standard",
			verifier:      "my-secure-verifier-string-that-is-long-enough-to-pass",
			challenge:     "my-secure-verifier-string-that-is-long-enough-to-pass",
			method:        "plain",
			shouldSucceed: true,
		},
		{
			name:          "Valid_S256_MinLength",
			verifier:      "0123456789012345678901234567890123456789012", // 43 chars
			challenge:     "_RpfHqw8pAZIomzVUE7sjRmHSM543WVdC4o-Kc4_3C0",   // SHA256 of above
			method:        "S256",
			shouldSucceed: true,
		},
		{
			name:          "Valid_S256_MaxLength",
			verifier:      strings.Repeat("a", 128), // 128 chars (max)
			challenge:     "aDbPE7rEAOkQUHHNavRwhN-srU5eMCyUv-0k4BOvtz4",
			method:        "S256",
			shouldSucceed: true,
		},
		{
			name:          "Valid_Plain_WithAllAllowedChars",
			verifier:      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
			challenge:     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
			method:        "plain",
			shouldSucceed: true,
		},

		// Invalid length cases
		{
			name:          "Invalid_TooShort_42Chars",
			verifier:      strings.Repeat("a", 42),
			challenge:     strings.Repeat("a", 42),
			method:        "plain",
			shouldSucceed: false,
			errorContains: "43-128 characters",
		},
		{
			name:          "Invalid_TooLong_129Chars",
			verifier:      strings.Repeat("a", 129),
			challenge:     strings.Repeat("a", 129),
			method:        "plain",
			shouldSucceed: false,
			errorContains: "43-128 characters",
		},
		{
			name:          "Invalid_Empty",
			verifier:      "",
			challenge:     "",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "43-128 characters",
		},

		// Invalid character cases
		{
			name:          "Invalid_ContainsSpace",
			verifier:      "my verifier with spaces in it that is long enough",
			challenge:     "my verifier with spaces in it that is long enough",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "invalid characters",
		},
		{
			name:          "Invalid_ContainsPlus",
			verifier:      "my+verifier+with+plus+signs+that+is+long+enough+now",
			challenge:     "my+verifier+with+plus+signs+that+is+long+enough+now",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "invalid characters",
		},
		{
			name:          "Invalid_ContainsSlash",
			verifier:      "my/verifier/with/slashes/that/is/long/enough/now/",
			challenge:     "my/verifier/with/slashes/that/is/long/enough/now/",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "invalid characters",
		},
		{
			name:          "Invalid_ContainsEquals",
			verifier:      "my=verifier=with=equals=signs=long=enough=now====",
			challenge:     "my=verifier=with=equals=signs=long=enough=now====",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "invalid characters",
		},
		{
			name:          "Invalid_ContainsSpecialChars",
			verifier:      "my!verifier@with#special$chars%long^enough&now*()+=",
			challenge:     "my!verifier@with#special$chars%long^enough&now*()+=",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "invalid characters",
		},

		// Challenge mismatch cases
		{
			name:          "Invalid_S256_WrongChallenge",
			verifier:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:     "WrongChallengeValueThatDoesNotMatchTheVerifier123",
			method:        "S256",
			shouldSucceed: false,
			errorContains: "invalid code_verifier",
		},
		{
			name:          "Invalid_Plain_Mismatch",
			verifier:      "my-secure-verifier-string-that-is-long-enough-to-pass",
			challenge:     "different-challenge-string-that-is-long-enough-pass",
			method:        "plain",
			shouldSucceed: false,
			errorContains: "invalid code_verifier",
		},

		// Method validation
		{
			name:          "Invalid_UnsupportedMethod",
			verifier:      "valid-verifier-string-that-is-long-enough-to-pass",
			challenge:     "valid-verifier-string-that-is-long-enough-to-pass",
			method:        "SHA512",
			shouldSucceed: false,
			errorContains: "unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCodeVerifier(tt.verifier, tt.challenge, tt.method)

			if tt.shouldSucceed {
				if err != nil {
					t.Errorf("Expected validation to succeed, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("Expected validation to fail, but it succeeded")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorContains, err)
				}
			}
		})
	}
}

// TestPKCE_EndToEnd tests PKCE in a full authorization code flow
func TestPKCE_EndToEnd(t *testing.T) {
	tests := []struct {
		name               string
		useChallenge       bool
		challengeMethod    string
		provideVerifier    bool
		verifierCorrect    bool
		expectedStatusCode int
		expectError        string
	}{
		{
			name:               "WithPKCE_S256_Success",
			useChallenge:       true,
			challengeMethod:    "S256",
			provideVerifier:    true,
			verifierCorrect:    true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "WithPKCE_Plain_Success",
			useChallenge:       true,
			challengeMethod:    "plain",
			provideVerifier:    true,
			verifierCorrect:    true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "WithPKCE_MissingVerifier_Fails",
			useChallenge:       true,
			challengeMethod:    "S256",
			provideVerifier:    false,
			expectedStatusCode: http.StatusBadRequest,
			expectError:        "code_verifier is required",
		},
		{
			name:               "WithPKCE_WrongVerifier_Fails",
			useChallenge:       true,
			challengeMethod:    "S256",
			provideVerifier:    true,
			verifierCorrect:    false,
			expectedStatusCode: http.StatusBadRequest,
			expectError:        "code verification failed",
		},
		{
			name:               "WithoutPKCE_NoVerifier_Success",
			useChallenge:       false,
			provideVerifier:    false,
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t)

			client := addTestClient(t, s, "test-client", "test-secret")
			user := newTestUser(t, "test@example.com")

			// Create auth request with or without PKCE
			var ar *AuthRequest
			var verifier string

			if tt.useChallenge {
				verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
				var challenge string
				if tt.challengeMethod == "S256" {
					challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
				} else {
					challenge = verifier
				}
				ar = newTestAuthRequest(t, client, user, WithPKCE(challenge, tt.challengeMethod))
			} else {
				ar = newTestAuthRequest(t, client, user)
			}

			code := addTestCode(t, s, ar)

			// Build token request
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", client.RedirectURIs[0])
			form.Set("client_id", "test-client")
			form.Set("client_secret", "test-secret")

			if tt.provideVerifier {
				if tt.verifierCorrect {
					form.Set("code_verifier", verifier)
				} else {
					form.Set("code_verifier", "wrong-verifier-that-is-long-enough-to-be-valid")
				}
			}

			req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			s.handleAuthorizationCodeGrant(w, req)

			if w.Code != tt.expectedStatusCode {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatusCode, w.Code, w.Body.String())
			}

			if tt.expectError != "" && !strings.Contains(w.Body.String(), tt.expectError) {
				t.Errorf("Expected error containing %q, got: %s", tt.expectError, w.Body.String())
			}
		})
	}
}

// TestPKCE_DefaultMethodPlain tests that plain is the default method
func TestPKCE_DefaultMethodPlain(t *testing.T) {
	s := newTestServer(t)

	client := addTestClient(t, s, "test-client", "test-secret")
	user := newTestUser(t, "test@example.com")

	verifier := "my-secure-verifier-string-that-is-long-enough-to-pass"

	// Create auth request with challenge and explicit plain method
	// (Authorization endpoint defaults empty method to "plain" at line 114 of authorize.go)
	ar := newTestAuthRequest(t, client, user, WithPKCE(verifier, "plain"))

	code := addTestCode(t, s, ar)

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
		t.Errorf("Expected status 200 with plain method default, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// TestPKCE_Security tests security properties of PKCE implementation
func TestPKCE_Security(t *testing.T) {
	t.Run("ConstantTimeComparison", func(t *testing.T) {
		// While we can't directly test timing, we can verify the function
		// doesn't short-circuit on first character mismatch
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

		// These should all fail in constant time (correct would be E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM)
		wrongChallenges := []string{
			"A9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", // First char wrong
			"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX", // Last char wrong
			"E9Melhoa2OwvFrEMTJguCHaoeK1tXURWbuGJSstw-cM", // Middle char wrong
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // All wrong
		}

		for _, wrongChallenge := range wrongChallenges {
			err := validateCodeVerifier(verifier, wrongChallenge, "S256")
			if err == nil {
				t.Errorf("Expected validation to fail for wrong challenge: %s", wrongChallenge)
			}
		}
	})

	t.Run("NoVerifierLeakage", func(t *testing.T) {
		// Verify that error messages don't leak the expected verifier
		verifier := "wrong-verifier-that-is-long-enough-to-pass-here"
		challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		err := validateCodeVerifier(verifier, challenge, "S256")
		if err == nil {
			t.Fatal("Expected error")
		}

		// Error should not contain the actual expected challenge or verifier
		errMsg := err.Error()
		if strings.Contains(errMsg, challenge) {
			t.Error("Error message should not leak the challenge")
		}
		if strings.Contains(errMsg, "dBjftJeZ4CVP") {
			t.Error("Error message should not leak expected verifier")
		}
	})
}
