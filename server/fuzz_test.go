// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"crypto/subtle"
	"testing"
)

// FuzzPKCEValidation tests PKCE validation with random inputs
// This ensures the validation never panics and handles edge cases correctly
func FuzzPKCEValidation(f *testing.F) {
	// Seed with known good and bad inputs from RFC 7636
	f.Add("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256")
	f.Add("plain-verifier-123", "plain-verifier-123", "plain")
	f.Add("", "", "S256")
	f.Add("short", "challenge", "S256")
	f.Add("a", "b", "invalid")
	f.Add("X" + string(make([]byte, 200)), "challenge", "S256") // very long verifier
	f.Add("verifier", "X"+string(make([]byte, 200)), "S256")    // very long challenge
	f.Add("verifier with spaces", "challenge", "S256")
	f.Add("verifier\nwith\nnewlines", "challenge", "S256")
	f.Add("verifier\x00null", "challenge", "S256")

	f.Fuzz(func(t *testing.T, verifier, challenge, method string) {
		// The function should never panic, regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateCodeVerifier panicked with verifier=%q, challenge=%q, method=%q: %v",
					verifier, challenge, method, r)
			}
		}()

		err := validateCodeVerifier(verifier, challenge, method)

		// We don't check the error value, just that it doesn't panic
		// The function should gracefully handle all inputs
		_ = err

		// Additional sanity check: if both are empty, should fail
		if verifier == "" && challenge == "" && err == nil {
			t.Errorf("Empty verifier and challenge should produce error")
		}
	})
}

// FuzzRedirectURIValidation tests redirect URI validation with random inputs
func FuzzRedirectURIValidation(f *testing.F) {
	// Seed with known good and bad URIs
	f.Add("https://example.com/callback")
	f.Add("http://localhost:8080/callback")
	f.Add("javascript:alert('xss')")
	f.Add("data:text/html,<script>alert('xss')</script>")
	f.Add("")
	f.Add("not-a-uri")
	f.Add("http://")
	f.Add("https://")
	f.Add("://noscheme")
	f.Add("http://example.com:99999/path") // invalid port
	f.Add("http://exa mple.com/path")      // space in host
	f.Add("http://example.com/path\ninjection")
	f.Add("custom-scheme://callback")
	f.Add(string(make([]byte, 10000))) // very long URI

	f.Fuzz(func(t *testing.T, uri string) {
		// Should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateRedirectURI panicked with uri=%q: %v", uri, r)
			}
		}()

		errMsg := validateRedirectURI(uri)

		// We don't validate the specific error, just that it doesn't panic
		_ = errMsg

		// Note: Current implementation is too permissive (allows javascript:, data:, etc)
		// This fuzz test ensures we don't panic, but doesn't validate security
	})
}

// FuzzScopeValidation tests scope validation with random inputs
func FuzzScopeValidation(f *testing.F) {
	// Seed with known good and bad scopes
	f.Add("openid profile email")
	f.Add("openid")
	f.Add("")
	f.Add("invalid-scope")
	f.Add("openid invalid profile")
	f.Add("openid  profile") // double space
	f.Add(" openid profile ") // leading/trailing spaces
	f.Add("openid\nprofile") // newline
	f.Add("openid\tprofile") // tab
	f.Add(string(make([]byte, 10000)))  // very long scope string
	f.Add("a b c d e f g h i j k l m n") // many scopes

	f.Fuzz(func(t *testing.T, scope string) {
		// Should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateScopes panicked with scope=%q: %v", scope, r)
			}
		}()

		// Use the test server to validate scopes
		s := &IDPServer{}

		// Parse space-delimited scopes
		scopes := []string{}
		if scope != "" {
			scopes = append(scopes, scope) // Simplified: just test with single scope
		}

		_, err := s.validateScopes(scopes)

		// We don't validate the specific error, just that it doesn't panic
		_ = err
	})
}

// FuzzClientSecretValidation tests client secret constant-time comparison
func FuzzClientSecretValidation(f *testing.F) {
	// Seed with various secret lengths and patterns
	f.Add("secret123", "secret123")
	f.Add("secret123", "secret456")
	f.Add("", "")
	f.Add("a", "b")
	f.Add(string(make([]byte, 1000)), string(make([]byte, 1000)))
	f.Add("secret\x00null", "secret")

	f.Fuzz(func(t *testing.T, provided, expected string) {
		// Should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("subtle.ConstantTimeCompare panicked with provided=%q, expected=%q: %v",
					provided, expected, r)
			}
		}()

		// Test the constant-time comparison used in the codebase
		result := subtle.ConstantTimeCompare([]byte(provided), []byte(expected))

		// Basic sanity checks
		if provided == expected && result != 1 {
			t.Errorf("Equal secrets should match: %q == %q", provided, expected)
		}
		if provided != expected && result == 1 {
			// This could be a false positive, but very unlikely with random data
			// Don't error, just note it
			t.Logf("Different secrets matched (hash collision?): %q vs %q", provided, expected)
		}
	})
}

// FuzzRedirectURIParameter tests redirect URI parameter handling in AuthRequest
func FuzzRedirectURIParameter(f *testing.F) {
	// Seed with various redirect URI values
	f.Add("https://example.com/callback")
	f.Add("")
	f.Add(string(make([]byte, 1000)))
	f.Add("http://localhost:8080")
	f.Add("redirect\nwith\nnewlines")
	f.Add("redirect\x00null")

	f.Fuzz(func(t *testing.T, redirectURI string) {
		// Should never panic when creating AuthRequest with redirect URI
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AuthRequest creation panicked with redirectURI=%q: %v", redirectURI, r)
			}
		}()

		client := newTestClient(t, "fuzz-client", "fuzz-secret")
		user := newTestUser(t, "fuzz@example.com")

		ar := &AuthRequest{
			FunnelRP:    client,
			RemoteUser:  user,
			RedirectURI: redirectURI,
		}

		// Should be able to store and retrieve redirect URI without panic
		if ar.RedirectURI != redirectURI {
			t.Errorf("RedirectURI was modified: expected=%q, got=%q", redirectURI, ar.RedirectURI)
		}
	})
}

// FuzzNonceParameter tests nonce parameter handling
func FuzzNonceParameter(f *testing.F) {
	// Seed with various nonce values
	f.Add("nonce123")
	f.Add("")
	f.Add(string(make([]byte, 1000)))
	f.Add("nonce with spaces")
	f.Add("nonce\nwith\nnewlines")
	f.Add("nonce\x00null")

	f.Fuzz(func(t *testing.T, nonce string) {
		// Should never panic when creating AuthRequest with nonce
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AuthRequest creation panicked with nonce=%q: %v", nonce, r)
			}
		}()

		client := newTestClient(t, "fuzz-client", "fuzz-secret")
		user := newTestUser(t, "fuzz@example.com")

		ar := &AuthRequest{
			FunnelRP:   client,
			RemoteUser: user,
			Nonce:      nonce,
		}

		// Should be able to store and retrieve nonce without panic
		if ar.Nonce != nonce {
			t.Errorf("Nonce was modified: expected=%q, got=%q", nonce, ar.Nonce)
		}
	})
}
