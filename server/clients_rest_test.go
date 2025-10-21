// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServeDeleteClientSuccess tests successful client deletion via REST API
func TestServeDeleteClientSuccess(t *testing.T) {
	s := newTestServer(t)

	// Add a test client
	clientID := "delete-me"
	addTestClient(t, s, clientID, "secret")

	// Add tokens for this client to verify they get cleaned up
	user := newTestUser(t, "test@example.com")
	client := s.funnelClients[clientID]
	ar := newTestAuthRequest(t, client, user)

	code := addTestCode(t, s, ar)
	token := addTestAccessToken(t, s, ar)
	refreshToken := addTestRefreshToken(t, s, ar)

	req := httptest.NewRequest("DELETE", "/clients/"+clientID, nil)
	w := httptest.NewRecorder()

	s.serveDeleteClient(w, req, clientID)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", resp.StatusCode)
	}

	// Verify client was deleted
	s.mu.Lock()
	_, exists := s.funnelClients[clientID]

	// Verify tokens were cleaned up
	_, codeExists := s.code[code]
	_, tokenExists := s.accessToken[token]
	_, refreshExists := s.refreshToken[refreshToken]
	s.mu.Unlock()

	if exists {
		t.Error("Client should have been deleted")
	}
	if codeExists {
		t.Error("Authorization codes for client should have been deleted")
	}
	if tokenExists {
		t.Error("Access tokens for client should have been deleted")
	}
	if refreshExists {
		t.Error("Refresh tokens for client should have been deleted")
	}
}

// TestServeDeleteClientNotFound tests deleting non-existent client
func TestServeDeleteClientNotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest("DELETE", "/clients/nonexistent", nil)
	w := httptest.NewRecorder()

	s.serveDeleteClient(w, req, "nonexistent")

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestServeDeleteClientWrongMethod tests wrong HTTP method
func TestServeDeleteClientWrongMethod(t *testing.T) {
	s := newTestServer(t)

	clientID := "test-client"
	addTestClient(t, s, clientID, "secret")

	req := httptest.NewRequest("GET", "/clients/"+clientID, nil)
	w := httptest.NewRecorder()

	s.serveDeleteClient(w, req, clientID)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

// TestLoadFunnelClientsSuccess tests loading clients from disk
func TestLoadFunnelClientsSuccess(t *testing.T) {
	tempDir := t.TempDir()
	s := New(nil, tempDir, false, false, false)

	// Create a test client file
	clients := map[string]*FunnelClient{
		"test-client": {
			ID:           "test-client",
			Secret:       "test-secret",
			Name:         "Test Client",
			RedirectURIs: []string{"https://example.com/callback"},
			CreatedAt:    time.Now(),
		},
	}

	data, err := json.Marshal(clients)
	if err != nil {
		t.Fatalf("Failed to marshal clients: %v", err)
	}

	clientsPath := filepath.Join(tempDir, funnelClientsFile)
	if err := os.WriteFile(clientsPath, data, 0600); err != nil {
		t.Fatalf("Failed to write clients file: %v", err)
	}

	// Load clients
	if err := s.LoadFunnelClients(); err != nil {
		t.Fatalf("LoadFunnelClients failed: %v", err)
	}

	// Verify client was loaded
	s.mu.Lock()
	client, exists := s.funnelClients["test-client"]
	s.mu.Unlock()

	if !exists {
		t.Fatal("Client should have been loaded")
	}

	if client.Name != "Test Client" {
		t.Errorf("Expected name 'Test Client', got '%s'", client.Name)
	}
}

// TestLoadFunnelClientsFileNotExist tests loading when file doesn't exist
func TestLoadFunnelClientsFileNotExist(t *testing.T) {
	tempDir := t.TempDir()
	s := New(nil, tempDir, false, false, false)

	// Should not error when file doesn't exist
	if err := s.LoadFunnelClients(); err != nil {
		t.Errorf("LoadFunnelClients should not error when file doesn't exist: %v", err)
	}
}

// TestLoadFunnelClientsMigration tests migration from old redirect_uri format
func TestLoadFunnelClientsMigration(t *testing.T) {
	tempDir := t.TempDir()
	s := New(nil, tempDir, false, false, false)

	// Create a client file with old format (redirect_uri instead of redirect_uris)
	oldFormatJSON := `{
		"old-client": {
			"client_id": "old-client",
			"client_secret": "old-secret",
			"client_name": "Old Format Client",
			"redirect_uri": "https://old.example.com/callback"
		}
	}`

	clientsPath := filepath.Join(tempDir, funnelClientsFile)
	if err := os.WriteFile(clientsPath, []byte(oldFormatJSON), 0600); err != nil {
		t.Fatalf("Failed to write clients file: %v", err)
	}

	// Load clients (should migrate)
	if err := s.LoadFunnelClients(); err != nil {
		t.Fatalf("LoadFunnelClients failed: %v", err)
	}

	// Verify migration happened
	s.mu.Lock()
	client, exists := s.funnelClients["old-client"]
	s.mu.Unlock()

	if !exists {
		t.Fatal("Client should have been loaded")
	}

	if len(client.RedirectURIs) != 1 {
		t.Fatalf("Expected 1 redirect URI after migration, got %d", len(client.RedirectURIs))
	}

	if client.RedirectURIs[0] != "https://old.example.com/callback" {
		t.Errorf("Expected migrated URI, got %s", client.RedirectURIs[0])
	}

	// Verify file was updated with migrated format
	data, err := os.ReadFile(clientsPath)
	if err != nil {
		t.Fatalf("Failed to read clients file: %v", err)
	}

	var migratedClients map[string]*FunnelClient
	if err := json.Unmarshal(data, &migratedClients); err != nil {
		t.Fatalf("Failed to unmarshal migrated clients: %v", err)
	}

	migratedClient := migratedClients["old-client"]
	if len(migratedClient.RedirectURIs) != 1 {
		t.Error("Migrated file should have redirect_uris array")
	}
}

// TestLoadFunnelClientsInvalidJSON tests handling of invalid JSON
func TestLoadFunnelClientsInvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	s := New(nil, tempDir, false, false, false)

	// Create invalid JSON file
	clientsPath := filepath.Join(tempDir, funnelClientsFile)
	if err := os.WriteFile(clientsPath, []byte("{invalid json}"), 0600); err != nil {
		t.Fatalf("Failed to write clients file: %v", err)
	}

	// Should error on invalid JSON
	if err := s.LoadFunnelClients(); err == nil {
		t.Error("LoadFunnelClients should error on invalid JSON")
	}
}

// TestServeClientsGET tests GET request to retrieve single client
func TestServeClientsGET(t *testing.T) {
	s := newTestServer(t)

	clientID := "get-test"
	client := addTestClient(t, s, clientID, "secret123")
	client.Name = "Get Test Client"

	req := httptest.NewRequest("GET", "/clients/"+clientID, nil)
	ctx := context.WithValue(req.Context(), appCapCtxKey, &accessGrantedRules{
		allowAdminUI: true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	s.serveClients(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var returnedClient FunnelClient
	if err := json.NewDecoder(resp.Body).Decode(&returnedClient); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if returnedClient.ID != clientID {
		t.Errorf("Expected ID %s, got %s", clientID, returnedClient.ID)
	}

	if returnedClient.Name != "Get Test Client" {
		t.Errorf("Expected name 'Get Test Client', got '%s'", returnedClient.Name)
	}

	// Secret should not be returned
	if returnedClient.Secret != "" {
		t.Error("Secret should not be returned in GET response")
	}
}

// TestServeGetClientsListSuccess tests listing all clients
func TestServeGetClientsListSuccess(t *testing.T) {
	s := newTestServer(t)

	// Add multiple clients
	client1 := addTestClient(t, s, "client1", "secret1")
	client1.Name = "Client One"

	client2 := addTestClient(t, s, "client2", "secret2")
	client2.Name = "Client Two"

	req := httptest.NewRequest("GET", "/clients/", nil)
	w := httptest.NewRecorder()

	s.serveGetClientsList(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var clients []*FunnelClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(clients))
	}

	// Verify secrets are not returned
	for _, c := range clients {
		if c.Secret != "" {
			t.Error("Secrets should not be returned in list")
		}
	}
}

// TestServeNewClientSuccess tests creating a new client via REST API
func TestServeNewClientSuccess(t *testing.T) {
	s := newTestServer(t)

	formData := "name=API+Client&redirect_uri=https://api.example.com/callback"
	req := httptest.NewRequest("POST", "/clients/new", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.serveNewClient(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var client FunnelClient
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if client.Name != "API Client" {
		t.Errorf("Expected name 'API Client', got '%s'", client.Name)
	}

	if client.ID == "" {
		t.Error("Client ID should be generated")
	}

	if client.Secret == "" {
		t.Error("Client secret should be generated")
	}
}

// TestGetFunnelClientsPath tests path resolution
func TestGetFunnelClientsPath(t *testing.T) {
	// With stateDir
	s := New(nil, "/custom/path", false, false, false)
	path := s.getFunnelClientsPath()
	expected := filepath.Join("/custom/path", funnelClientsFile)
	if path != expected {
		t.Errorf("Expected path %s, got %s", expected, path)
	}

	// Without stateDir
	s2 := New(nil, "", false, false, false)
	path2 := s2.getFunnelClientsPath()
	if path2 != funnelClientsFile {
		t.Errorf("Expected path %s, got %s", funnelClientsFile, path2)
	}
}
