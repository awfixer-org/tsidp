// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUIHandleUIFunnelBlocked tests that UI is blocked over funnel
func TestUIHandleUIFunnelBlocked(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Tailscale-Funnel-Request", "true")
	// Set app capability context (required before funnel check)
	ctx := context.WithValue(req.Context(), appCapCtxKey, &accessGrantedRules{
		allowAdminUI: true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	s.handleUI(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

// TestUIHandleUINoAppCap tests that UI requires app capability context
func TestUIHandleUINoAppCap(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	// No app capability context set
	w := httptest.NewRecorder()

	s.handleUI(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

// TestUIHandleUINoAdminUIPermission tests that UI requires allowAdminUI
func TestUIHandleUINoAdminUIPermission(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	// Set app capability context but without allowAdminUI
	ctx := context.WithValue(req.Context(), appCapCtxKey, &accessGrantedRules{
		allowAdminUI: false,
		allowDCR:     false,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	s.handleUI(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

// TestUIHandleUIClientsList tests routing to client list
func TestUIHandleUIClientsList(t *testing.T) {
	s := newTestServer(t)

	// Add a test client
	addTestClient(t, s, "test-client", "test-secret")

	req := httptest.NewRequest("GET", "/", nil)
	// Set proper app capability context
	ctx := context.WithValue(req.Context(), appCapCtxKey, &accessGrantedRules{
		allowAdminUI: true,
		allowDCR:     false,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	s.handleUI(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Should contain the client in the list
	if !strings.Contains(bodyStr, "test-client") {
		t.Error("Client list should contain test-client")
	}
}

// TestUIHandleUIStyleCSS tests serving CSS file
func TestUIHandleUIStyleCSS(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/style.css", nil)
	ctx := context.WithValue(req.Context(), appCapCtxKey, &accessGrantedRules{
		allowAdminUI: true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	s.handleUI(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Should have CSS content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/css") && !strings.Contains(contentType, "text/plain") {
		// http.ServeContent may set different content types
		t.Logf("Note: Content-Type is %s", contentType)
	}
}

// TestUIHandleUI404 tests 404 for unknown paths
func TestUIHandleUI404(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	ctx := context.WithValue(req.Context(), appCapCtxKey, &accessGrantedRules{
		allowAdminUI: true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	s.handleUI(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestHandleClientsListEmpty tests empty client list
func TestHandleClientsListEmpty(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	s.handleClientsList(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Should render HTML with empty list
	if len(bodyStr) < 10 {
		t.Error("Should render HTML content")
	}
}

// TestHandleClientsListMultipleClients tests sorting of client list
func TestHandleClientsListMultipleClients(t *testing.T) {
	s := newTestServer(t)

	// Add clients in non-alphabetical order
	addTestClient(t, s, "zebra-client", "secret1").Name = "Zebra App"
	addTestClient(t, s, "alpha-client", "secret2").Name = "Alpha App"
	addTestClient(t, s, "beta-client", "secret3").Name = "Beta App"

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	s.handleClientsList(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// All clients should be present
	if !strings.Contains(bodyStr, "Zebra App") {
		t.Error("Should contain Zebra App")
	}
	if !strings.Contains(bodyStr, "Alpha App") {
		t.Error("Should contain Alpha App")
	}
	if !strings.Contains(bodyStr, "Beta App") {
		t.Error("Should contain Beta App")
	}

	// They should be sorted by name
	alphaIdx := strings.Index(bodyStr, "Alpha App")
	betaIdx := strings.Index(bodyStr, "Beta App")
	zebraIdx := strings.Index(bodyStr, "Zebra App")

	if alphaIdx == -1 || betaIdx == -1 || zebraIdx == -1 {
		t.Fatal("All client names should be present")
	}

	if !(alphaIdx < betaIdx && betaIdx < zebraIdx) {
		t.Error("Clients should be sorted alphabetically: Alpha, Beta, Zebra")
	}
}

// TestHandleClientsListSameName tests sorting by ID when names are same
func TestHandleClientsListSameName(t *testing.T) {
	s := newTestServer(t)

	// Add clients with same name but different IDs
	client1 := addTestClient(t, s, "zzz-id", "secret1")
	client1.Name = "Same Name"

	client2 := addTestClient(t, s, "aaa-id", "secret2")
	client2.Name = "Same Name"

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	s.handleClientsList(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Both should be present, sorted by ID
	aaaIdx := strings.Index(bodyStr, "aaa-id")
	zzzIdx := strings.Index(bodyStr, "zzz-id")

	if aaaIdx == -1 || zzzIdx == -1 {
		t.Fatal("Both client IDs should be present")
	}

	if aaaIdx > zzzIdx {
		t.Error("When names are same, should be sorted by ID (aaa-id before zzz-id)")
	}
}
