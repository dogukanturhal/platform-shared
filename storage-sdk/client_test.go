// SPDX-License-Identifier: Apache-2.0

package storagesdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ------------------------------------------------------------------
// NewStorageClient validation
// ------------------------------------------------------------------

func TestNewStorageClient_Validation(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name:    "empty StorageAPIURL",
			opts:    Options{},
			wantErr: true,
		},
		{
			name:    "invalid URL",
			opts:    Options{StorageAPIURL: "not-a-url"},
			wantErr: true,
		},
		{
			name:    "valid minimal options",
			opts:    Options{StorageAPIURL: "http://storage-api:8020"},
			wantErr: false,
		},
		{
			name: "valid with custom HTTP client",
			opts: Options{
				StorageAPIURL: "http://storage-api:8020",
				HTTPClient:    &http.Client{Timeout: 5 * time.Second},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewStorageClient(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil {
				t.Fatal("expected non-nil client")
			}
		})
	}
}

// ------------------------------------------------------------------
// PresignedUpload
// ------------------------------------------------------------------

func TestPresignedUpload_Success(t *testing.T) {
	tenantID := uuid.New()
	bucketID := uuid.New()
	expiresAt := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		wantPath := "/api/v1/storage/buckets/" + bucketID.String() + "/objects/presign"
		if r.URL.Path != wantPath {
			t.Errorf("path = %q; want %q", r.URL.Path, wantPath)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q; want application/json", ct)
		}

		// Decode the request body and validate fields.
		var body struct {
			ObjectKey   string `json:"object_key"`
			ContentType string `json:"content_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.ObjectKey != "crm/logos/logo.png" {
			t.Errorf("object_key = %q; want crm/logos/logo.png", body.ObjectKey)
		}

		_ = json.NewEncoder(w).Encode(PresignedUploadResponse{
			UploadURL: "https://minio:9000/bucket/crm/logos/logo.png?X-Amz-Signature=abc",
			ExpiresAt: expiresAt,
			Method:    "PUT",
		})
	}))
	defer server.Close()

	client, err := NewStorageClient(Options{StorageAPIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.PresignedUpload(context.Background(), &PresignedUploadRequest{
		TenantID:    tenantID,
		BucketID:    bucketID,
		ObjectKey:   "crm/logos/logo.png",
		ContentType: "image/png",
	})
	if err != nil {
		t.Fatalf("PresignedUpload: %v", err)
	}
	if resp.UploadURL == "" {
		t.Error("expected non-empty UploadURL")
	}
	if resp.Method != "PUT" {
		t.Errorf("Method = %q; want PUT", resp.Method)
	}
	if !resp.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v; want %v", resp.ExpiresAt, expiresAt)
	}
}

func TestPresignedUpload_DefaultMethod(t *testing.T) {
	bucketID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Respond without the Method field to exercise the default.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url":        "https://minio/upload",
			"expires_at": time.Now().Add(time.Minute),
		})
	}))
	defer server.Close()

	client, _ := NewStorageClient(Options{StorageAPIURL: server.URL})
	resp, err := client.PresignedUpload(context.Background(), &PresignedUploadRequest{
		BucketID:  bucketID,
		ObjectKey: "any/key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Method != http.MethodPut {
		t.Errorf("Method = %q; want PUT", resp.Method)
	}
}

func TestPresignedUpload_Validation(t *testing.T) {
	client, _ := NewStorageClient(Options{StorageAPIURL: "http://localhost:8020"})
	ctx := context.Background()

	tests := []struct {
		name    string
		req     *PresignedUploadRequest
		wantErr string
	}{
		{"nil request", nil, "nil"},
		{"nil BucketID", &PresignedUploadRequest{ObjectKey: "k"}, "BucketID"},
		{"empty ObjectKey", &PresignedUploadRequest{BucketID: uuid.New()}, "ObjectKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.PresignedUpload(ctx, tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// ------------------------------------------------------------------
// PresignedDownload
// ------------------------------------------------------------------

func TestPresignedDownload_Success(t *testing.T) {
	tenantID := uuid.New()
	bucketID := uuid.New()
	expiresAt := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}

		_ = json.NewEncoder(w).Encode(PresignedDownloadResponse{
			DownloadURL: "https://minio:9000/bucket/docs/report.pdf?X-Amz-Signature=xyz",
			ExpiresAt:   expiresAt,
			Method:      "GET",
		})
	}))
	defer server.Close()

	client, _ := NewStorageClient(Options{StorageAPIURL: server.URL})
	resp, err := client.PresignedDownload(context.Background(), &PresignedDownloadRequest{
		TenantID:  tenantID,
		BucketID:  bucketID,
		ObjectKey: "docs/report.pdf",
	})
	if err != nil {
		t.Fatalf("PresignedDownload: %v", err)
	}
	if resp.DownloadURL == "" {
		t.Error("expected non-empty DownloadURL")
	}
	if resp.Method != "GET" {
		t.Errorf("Method = %q; want GET", resp.Method)
	}
}

func TestPresignedDownload_ExpiryMinsInQuery(t *testing.T) {
	bucketID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if em := r.URL.Query().Get("expiry_mins"); em != "60" {
			t.Errorf("expiry_mins = %q; want 60", em)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"url":        "https://minio/dl",
			"expires_at": time.Now().Add(time.Hour),
			"method":     "GET",
		})
	}))
	defer server.Close()

	client, _ := NewStorageClient(Options{StorageAPIURL: server.URL})
	_, err := client.PresignedDownload(context.Background(), &PresignedDownloadRequest{
		BucketID:   bucketID,
		ObjectKey:  "some/key",
		ExpiryMins: 60,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPresignedDownload_Validation(t *testing.T) {
	client, _ := NewStorageClient(Options{StorageAPIURL: "http://localhost:8020"})
	ctx := context.Background()

	tests := []struct {
		name string
		req  *PresignedDownloadRequest
	}{
		{"nil request", nil},
		{"nil BucketID", &PresignedDownloadRequest{ObjectKey: "k"}},
		{"empty ObjectKey", &PresignedDownloadRequest{BucketID: uuid.New()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.PresignedDownload(ctx, tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// ------------------------------------------------------------------
// DeleteObject
// ------------------------------------------------------------------

func TestDeleteObject_Success(t *testing.T) {
	tenantID := uuid.New()
	bucketID := uuid.New()
	objectKey := "docs/old-report.pdf"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, _ := NewStorageClient(Options{StorageAPIURL: server.URL})
	if err := client.DeleteObject(context.Background(), tenantID, bucketID, objectKey); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
}

func TestDeleteObject_Validation(t *testing.T) {
	client, _ := NewStorageClient(Options{StorageAPIURL: "http://localhost:8020"})
	ctx := context.Background()
	validID := uuid.New()

	tests := []struct {
		name      string
		tenantID  uuid.UUID
		bucketID  uuid.UUID
		objectKey string
	}{
		{"nil tenantID", uuid.Nil, validID, "key"},
		{"nil bucketID", validID, uuid.Nil, "key"},
		{"empty objectKey", validID, validID, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.DeleteObject(ctx, tt.tenantID, tt.bucketID, tt.objectKey)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// ------------------------------------------------------------------
// Error handling
// ------------------------------------------------------------------

func TestStorageClient_ErrorResponses(t *testing.T) {
	tests := []struct {
		name           string
		serverStatus   int
		serverBody     string
		wantStatusCode int
	}{
		{"unauthorized", 401, `{"error":"unauthorized"}`, 401},
		{"forbidden", 403, `{"error":"forbidden"}`, 403},
		{"not found", 404, `{"error":"bucket not found"}`, 404},
		{"quota exceeded", 507, `{"error":"quota exceeded"}`, 507},
		{"server error", 500, `{"error":"internal error"}`, 500},
	}

	bucketID := uuid.New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			client, _ := NewStorageClient(Options{StorageAPIURL: server.URL})
			_, err := client.PresignedUpload(context.Background(), &PresignedUploadRequest{
				BucketID:  bucketID,
				ObjectKey: "test/key",
			})

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var se *StorageError
			if !errors.As(err, &se) {
				t.Fatalf("expected *StorageError, got %T", err)
			}

			if se.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d; want %d", se.StatusCode, tt.wantStatusCode)
			}
		})
	}
}

func TestStorageClient_ContextCancellation(t *testing.T) {
	bucketID := uuid.New()

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Simulate a slow response — the context will cancel before this returns.
		<-r.Context().Done()
	}))
	defer server.Close()

	client, _ := NewStorageClient(Options{StorageAPIURL: server.URL})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.PresignedUpload(ctx, &PresignedUploadRequest{
		BucketID:  bucketID,
		ObjectKey: "test/key",
	})
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}

// ------------------------------------------------------------------
// StorageError
// ------------------------------------------------------------------

func TestStorageError_Error(t *testing.T) {
	se := &StorageError{StatusCode: 404, Message: "object not found"}
	want := "storagesdk: HTTP 404: object not found"
	if got := se.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

func TestStorageErrorFromStatus_Sentinels(t *testing.T) {
	tests := []struct {
		status int
		want   *StorageError
	}{
		{401, ErrUnauthorized},
		{403, ErrForbidden},
		{404, ErrNotFound},
		{507, ErrQuotaExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.want.Message, func(t *testing.T) {
			got := storageErrorFromStatus(tt.status, "")
			if got != tt.want {
				t.Errorf("storageErrorFromStatus(%d) returned different sentinel than expected", tt.status)
			}
		})
	}
}

func TestStorageErrorFromStatus_Unknown(t *testing.T) {
	se := storageErrorFromStatus(422, "validation failed")
	if se.StatusCode != 422 {
		t.Errorf("StatusCode = %d; want 422", se.StatusCode)
	}
	if se.Message != "validation failed" {
		t.Errorf("Message = %q; want 'validation failed'", se.Message)
	}
}
