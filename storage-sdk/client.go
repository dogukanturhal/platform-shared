// SPDX-License-Identifier: Apache-2.0

// Package storagesdk provides a thin HTTP client for the storage-api control
// plane. Services import this package instead of creating their own MinIO
// clients; all MinIO access is mediated through the storage-api.
//
// Typical wiring with service-to-service auth:
//
//	tokenClient, _ := serviceauth.NewTokenClient(serviceauth.TokenClientConfig{...})
//	storageClient := storagesdk.NewStorageClient(storagesdk.Options{
//	    StorageAPIURL: "http://storage-api:8020",
//	    HTTPClient:    &http.Client{Transport: tokenClient.RoundTripper(nil)},
//	})
//
//	// Generate a presigned upload URL and hand it to the end-user.
//	resp, err := storageClient.PresignedUpload(ctx, &storagesdk.PresignedUploadRequest{
//	    TenantID:    tenantID,
//	    BucketID:    bucketID,
//	    ObjectKey:   "crm/logos/logo.png",
//	    ContentType: "image/png",
//	})
//	// resp.UploadURL → caller PUTs the file bytes here directly.
package storagesdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Options configures a StorageClient.
type Options struct {
	// StorageAPIURL is the base URL of the storage-api service.
	// Example: "http://storage-api:8020"
	// The value must not have a trailing slash.
	StorageAPIURL string

	// HTTPClient is an optional pre-configured HTTP client. Callers typically
	// wrap this with a service-auth RoundTripper so that every request carries
	// a valid service JWT automatically:
	//
	//   tokenClient.RoundTripper(nil)
	//
	// When nil, a default client with a 30-second timeout is used. Note that
	// this default client carries no auth headers, which will cause storage-api
	// to reject all requests in non-development environments.
	HTTPClient *http.Client

	// Logger is an optional SugaredLogger for debug and error output.
	// When nil, all logging is silently suppressed.
	Logger *zap.SugaredLogger
}

// StorageClient is a thin HTTP client for the storage-api control plane.
// All methods are safe for concurrent use.
type StorageClient struct {
	baseURL    string
	httpClient *http.Client
	log        *zap.SugaredLogger
}

// NewStorageClient creates a new StorageClient from the given Options.
// It returns an error if StorageAPIURL is empty or not a valid URL.
func NewStorageClient(opts Options) (*StorageClient, error) {
	if opts.StorageAPIURL == "" {
		return nil, errors.New("storagesdk: StorageAPIURL must not be empty")
	}
	if _, err := url.ParseRequestURI(opts.StorageAPIURL); err != nil {
		return nil, fmt.Errorf("storagesdk: invalid StorageAPIURL %q: %w", opts.StorageAPIURL, err)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &StorageClient{
		baseURL:    opts.StorageAPIURL,
		httpClient: httpClient,
		log:        opts.Logger,
	}, nil
}

// PresignedUpload requests a presigned PUT URL from the storage-api.
// The caller is responsible for uploading the file bytes directly to MinIO
// using the URL in the response — this method does not transfer any bytes.
//
// The BucketID in the request must correspond to an existing bucket that
// belongs to the specified TenantID.
func (c *StorageClient) PresignedUpload(ctx context.Context, req *PresignedUploadRequest) (*PresignedUploadResponse, error) {
	if req == nil {
		return nil, errors.New("storagesdk: PresignedUpload: request must not be nil")
	}
	if req.BucketID == uuid.Nil {
		return nil, errors.New("storagesdk: PresignedUpload: BucketID must not be nil")
	}
	if req.ObjectKey == "" {
		return nil, errors.New("storagesdk: PresignedUpload: ObjectKey must not be empty")
	}

	// The storage-api path is POST /api/v1/storage/buckets/{bucketID}/objects/presign
	path := fmt.Sprintf("/api/v1/storage/buckets/%s/objects/presign", req.BucketID)

	// The storage-api's PresignedURLRequest only needs ObjectKey, ContentType, ExpiryMins.
	body := struct {
		ObjectKey   string `json:"object_key"`
		ContentType string `json:"content_type,omitempty"`
		ExpiryMins  int    `json:"expiry_mins,omitempty"`
	}{
		ObjectKey:   req.ObjectKey,
		ContentType: req.ContentType,
		ExpiryMins:  req.ExpiryMins,
	}

	var resp PresignedUploadResponse
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		c.logf("PresignedUpload failed: bucket=%s key=%s err=%v", req.BucketID, req.ObjectKey, err)
		return nil, err
	}

	if resp.Method == "" {
		resp.Method = http.MethodPut
	}
	return &resp, nil
}

// PresignedDownload requests a presigned GET URL from the storage-api.
// The returned URL can be given directly to an end-user browser or used by
// the calling service to stream the object — no further auth is needed.
//
// The BucketID in the request must correspond to an existing bucket that
// belongs to the specified TenantID.
func (c *StorageClient) PresignedDownload(ctx context.Context, req *PresignedDownloadRequest) (*PresignedDownloadResponse, error) {
	if req == nil {
		return nil, errors.New("storagesdk: PresignedDownload: request must not be nil")
	}
	if req.BucketID == uuid.Nil {
		return nil, errors.New("storagesdk: PresignedDownload: BucketID must not be nil")
	}
	if req.ObjectKey == "" {
		return nil, errors.New("storagesdk: PresignedDownload: ObjectKey must not be empty")
	}

	// The storage-api path is GET /api/v1/storage/buckets/{bucketID}/objects/{key}
	// The key is URL-encoded and the leading slash is stripped server-side.
	encodedKey := url.PathEscape(req.ObjectKey)
	path := fmt.Sprintf("/api/v1/storage/buckets/%s/objects/%s", req.BucketID, encodedKey)

	if req.ExpiryMins > 0 {
		path += "?expiry_mins=" + strconv.Itoa(req.ExpiryMins)
	}

	var resp PresignedDownloadResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		c.logf("PresignedDownload failed: bucket=%s key=%s err=%v", req.BucketID, req.ObjectKey, err)
		return nil, err
	}

	if resp.Method == "" {
		resp.Method = http.MethodGet
	}
	return &resp, nil
}

// DeleteObject requests deletion of an object from the storage-api.
// The storage-api removes the object from MinIO and updates bucket usage
// counters. The tenantID is passed as a query parameter so the storage-api
// can enforce cross-tenant isolation.
func (c *StorageClient) DeleteObject(ctx context.Context, tenantID uuid.UUID, bucketID uuid.UUID, objectKey string) error {
	if tenantID == uuid.Nil {
		return errors.New("storagesdk: DeleteObject: tenantID must not be nil")
	}
	if bucketID == uuid.Nil {
		return errors.New("storagesdk: DeleteObject: bucketID must not be nil")
	}
	if objectKey == "" {
		return errors.New("storagesdk: DeleteObject: objectKey must not be empty")
	}

	encodedKey := url.PathEscape(objectKey)
	path := fmt.Sprintf("/api/v1/storage/buckets/%s/objects/%s?tenant_id=%s",
		bucketID, encodedKey, tenantID)

	if err := c.doJSON(ctx, http.MethodDelete, path, nil, nil); err != nil {
		c.logf("DeleteObject failed: tenant=%s bucket=%s key=%s err=%v",
			tenantID, bucketID, objectKey, err)
		return err
	}
	return nil
}

// UploadPlatformAsset uploads a platform-level asset (e.g. connector icons)
// to the shared bucket via the storage-api's internal control plane. These
// assets are not tenant-scoped and are accessible at the public MinIO URL.
//
// The upload is idempotent: if the object already exists, storage-api skips it.
func (c *StorageClient) UploadPlatformAsset(ctx context.Context, req *PlatformAssetUploadRequest) (*PlatformAssetUploadResponse, error) {
	if req == nil {
		return nil, errors.New("storagesdk: UploadPlatformAsset: request must not be nil")
	}
	if req.Bucket == "" {
		return nil, errors.New("storagesdk: UploadPlatformAsset: Bucket must not be empty")
	}
	if req.ObjectKey == "" {
		return nil, errors.New("storagesdk: UploadPlatformAsset: ObjectKey must not be empty")
	}

	var resp PlatformAssetUploadResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/internal/storage/platform-assets", req, &resp); err != nil {
		c.logf("UploadPlatformAsset failed: bucket=%s key=%s err=%v", req.Bucket, req.ObjectKey, err)
		return nil, err
	}
	return &resp, nil
}

// doJSON performs an HTTP request against the storage-api, marshalling body
// (if non-nil) as JSON and unmarshalling a 2xx response body into out (if
// non-nil). Non-2xx responses are decoded and returned as *StorageError.
func (c *StorageClient) doJSON(ctx context.Context, method, path string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("storagesdk: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("storagesdk: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("storagesdk: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Attempt to extract the error message from the JSON envelope.
		var apiErr apiErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		return storageErrorFromStatus(resp.StatusCode, apiErr.Error)
	}

	// No output expected (e.g. DELETE returning 204).
	if out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("storagesdk: decode response from %s %s: %w", method, path, err)
	}
	return nil
}

// logf logs at error level when a logger is configured; otherwise it is a no-op.
func (c *StorageClient) logf(format string, args ...any) {
	if c.log != nil {
		c.log.Errorf(format, args...)
	}
}
