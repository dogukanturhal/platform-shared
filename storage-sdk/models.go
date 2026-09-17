// SPDX-License-Identifier: Apache-2.0

package storagesdk

import (
	"time"

	"github.com/google/uuid"
)

// PresignedUploadRequest is the payload sent to the storage-api to obtain a
// time-limited PUT URL. The caller uploads the file directly to MinIO using
// the returned URL — the SDK never touches the file bytes.
type PresignedUploadRequest struct {
	// TenantID scopes the request to a specific tenant's bucket.
	TenantID uuid.UUID `json:"tenant_id"`

	// BucketID identifies the pre-provisioned tenant bucket to upload into.
	// Obtain this by creating a bucket via the storage-api's bucket CRUD
	// endpoints before calling PresignedUpload.
	BucketID uuid.UUID `json:"bucket_id"`

	// ObjectKey is the destination path within the bucket (e.g. "crm/logos/logo.png").
	// The key is used as-is; callers are responsible for namespacing.
	ObjectKey string `json:"object_key"`

	// ContentType is the MIME type of the object (e.g. "image/png").
	ContentType string `json:"content_type,omitempty"`

	// ExpiryMins is how long the presigned URL remains valid.
	// Zero means the storage-api uses its default (typically 15 minutes).
	ExpiryMins int `json:"expiry_mins,omitempty"`
}

// PresignedUploadResponse holds the URL the caller should PUT the file bytes to,
// together with metadata the caller may need to track the upload.
type PresignedUploadResponse struct {
	// UploadURL is the presigned PUT URL. The caller sends the file bytes here
	// directly; no Authorization header is needed.
	UploadURL string `json:"url"`

	// ExpiresAt is when the URL stops being valid.
	ExpiresAt time.Time `json:"expires_at"`

	// Method is always "PUT" for upload URLs.
	Method string `json:"method"`
}

// PresignedDownloadRequest is the payload sent to the storage-api to obtain a
// time-limited GET URL.
type PresignedDownloadRequest struct {
	// TenantID scopes the lookup to a specific tenant's bucket.
	TenantID uuid.UUID `json:"tenant_id"`

	// BucketID identifies the bucket that holds the object.
	BucketID uuid.UUID `json:"bucket_id"`

	// ObjectKey is the path of the object within the bucket.
	ObjectKey string `json:"object_key"`

	// ExpiryMins is how long the presigned URL remains valid.
	// Zero means the storage-api uses its default (typically 15 minutes).
	ExpiryMins int `json:"expiry_mins,omitempty"`
}

// PresignedDownloadResponse holds the URL the caller (or end-user browser) can
// use to download the object.
type PresignedDownloadResponse struct {
	// DownloadURL is the presigned GET URL.
	DownloadURL string `json:"url"`

	// ExpiresAt is when the URL stops being valid.
	ExpiresAt time.Time `json:"expires_at"`

	// Method is always "GET" for download URLs.
	Method string `json:"method"`
}

// PlatformAssetUploadRequest is the payload for uploading platform-level assets
// (e.g. connector icons, shared branding) directly to a shared MinIO bucket.
// These assets are not tenant-scoped.
type PlatformAssetUploadRequest struct {
	// Bucket is the MinIO bucket name (e.g. "example").
	Bucket string `json:"bucket"`

	// ObjectKey is the destination path within the bucket (e.g. "icons/connectors/discord.svg").
	ObjectKey string `json:"object_key"`

	// ContentType is the MIME type of the asset (e.g. "image/svg+xml").
	ContentType string `json:"content_type"`

	// Data is the base64-encoded file content.
	Data string `json:"data"`
}

// PlatformAssetUploadResponse is returned after a successful platform asset upload.
type PlatformAssetUploadResponse struct {
	ObjectKey string `json:"object_key"`
	Bucket    string `json:"bucket"`
	Status    string `json:"status"`
}

// apiErrorResponse mirrors the JSON error envelope returned by the storage-api.
// It is used internally to decode non-2xx responses.
type apiErrorResponse struct {
	Error string `json:"error"`
}
