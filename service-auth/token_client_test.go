// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTokenClient_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     TokenClientConfig
		wantErr string
	}{
		{"empty TokenURL", TokenClientConfig{ClientID: "x", ClientSecret: "y"}, "TokenURL"},
		{"empty ClientID", TokenClientConfig{TokenURL: "http://x", ClientSecret: "y"}, "ClientID"},
		{"empty ClientSecret", TokenClientConfig{TokenURL: "http://x", ClientID: "y"}, "ClientSecret"},
		{"valid", TokenClientConfig{TokenURL: "http://x", ClientID: "y", ClientSecret: "z"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTokenClient(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			}
		})
	}
}

func TestTokenClient_GetToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "svc-test" {
			t.Errorf("client_id = %q", r.Form.Get("client_id"))
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:gosec // test token
			"access_token": "test-jwt-token-1234",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	tc, err := NewTokenClient(TokenClientConfig{
		TokenURL:     server.URL,
		ClientID:     "svc-test",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}

	token, err := tc.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "test-jwt-token-1234" { //nolint:gosec // test token comparison
		t.Errorf("token = %q; want test-jwt-token-1234", token)
	}
}

func TestTokenClient_CachesToken(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cached-token",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	tc, _ := NewTokenClient(TokenClientConfig{
		TokenURL:     server.URL,
		ClientID:     "svc-test",
		ClientSecret: "test-secret",
	})

	// First call fetches from server
	tok1, _ := tc.GetToken()
	// Second call should use cache
	tok2, _ := tc.GetToken()

	if tok1 != tok2 {
		t.Error("expected same token from cache")
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("expected 1 server call, got %d", callCount)
	}
}

func TestTokenClient_ConcurrentAccess(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		// Simulate some latency
		time.Sleep(10 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "concurrent-token",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	tc, _ := NewTokenClient(TokenClientConfig{
		TokenURL:     server.URL,
		ClientID:     "svc-test",
		ClientSecret: "test-secret",
	})

	// Launch 10 concurrent goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := tc.GetToken()
			if err != nil {
				t.Errorf("GetToken: %v", err)
			}
			if tok != "concurrent-token" {
				t.Errorf("unexpected token: %q", tok)
			}
		}()
	}
	wg.Wait()

	// Due to double-check locking, only 1 request should hit the server.
	if count := atomic.LoadInt32(&callCount); count != 1 {
		t.Errorf("expected 1 server call, got %d", count)
	}
}

func TestTokenClient_RoundTripper(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "rt-token-5678",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer tokenServer.Close()

	tc, _ := NewTokenClient(TokenClientConfig{
		TokenURL:     tokenServer.URL,
		ClientID:     "svc-test",
		ClientSecret: "test-secret",
	})

	// Create a test target server that checks for the Bearer header.
	var receivedAuth string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer targetServer.Close()

	client := &http.Client{Transport: tc.RoundTripper(nil)}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetServer.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if receivedAuth != "Bearer rt-token-5678" {
		t.Errorf("Authorization = %q; want 'Bearer rt-token-5678'", receivedAuth)
	}
}

func TestTokenClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	tc, _ := NewTokenClient(TokenClientConfig{
		TokenURL:     server.URL,
		ClientID:     "svc-test",
		ClientSecret: "wrong-secret",
	})

	_, err := tc.GetToken()
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}
