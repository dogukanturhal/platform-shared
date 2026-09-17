// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"errors"
	"testing"
	"time"
)

func TestNewIAMHTTPClient_MissingCreds(t *testing.T) {
	tests := []struct {
		name string
		cfg  IAMHTTPClientConfig
	}{
		{"empty ClientID", IAMHTTPClientConfig{IAMURL: "http://iam", ClientID: "", ClientSecret: "s"}},
		{"empty ClientSecret", IAMHTTPClientConfig{IAMURL: "http://iam", ClientID: "svc", ClientSecret: ""}},
		{"both empty", IAMHTTPClientConfig{IAMURL: "http://iam"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewIAMHTTPClient(tt.cfg)
			if !errors.Is(err, ErrMissingCredentials) {
				t.Fatalf("expected ErrMissingCredentials, got %v", err)
			}
			if client == nil {
				t.Fatal("expected non-nil fallback client")
			}
			if client.Timeout != 10*time.Second {
				t.Errorf("expected default 10s timeout, got %v", client.Timeout)
			}
			if client.Transport != nil {
				t.Error("fallback client must not have a token RoundTripper attached")
			}
		})
	}
}

func TestNewIAMHTTPClient_Success(t *testing.T) {
	client, err := NewIAMHTTPClient(IAMHTTPClientConfig{
		IAMURL:       "http://iam",
		ClientID:     "svc-test",
		ClientSecret: "sekret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil || client.Transport == nil {
		t.Fatal("expected authenticated client with Transport set")
	}
}

func TestNewIAMHTTPClient_CustomTimeout(t *testing.T) {
	client, err := NewIAMHTTPClient(IAMHTTPClientConfig{
		IAMURL:       "http://iam",
		ClientID:     "svc-test",
		ClientSecret: "sekret",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.Timeout != 2*time.Second {
		t.Errorf("expected 2s timeout, got %v", client.Timeout)
	}
}
