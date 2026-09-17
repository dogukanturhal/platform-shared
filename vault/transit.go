// SPDX-License-Identifier: Apache-2.0

// Package vault provides Transit engine encryption/decryption functionality.
package vault

import (
	"context"
	"encoding/base64"
	"fmt"
)

// TransitConfig holds configuration for the Transit secrets engine.
type TransitConfig struct {
	// Enabled determines if Transit encryption is active.
	Enabled bool `mapstructure:"VAULT_TRANSIT_ENABLED"`

	// MountPath is the mount path for the Transit engine.
	MountPath string `mapstructure:"VAULT_TRANSIT_MOUNT_PATH"`

	// DefaultKeyName is the default encryption key to use.
	DefaultKeyName string `mapstructure:"VAULT_TRANSIT_DEFAULT_KEY"`
}

// DefaultTransitConfig returns a TransitConfig with sensible defaults.
func DefaultTransitConfig() TransitConfig {
	return TransitConfig{
		Enabled:        false,
		MountPath:      "transit",
		DefaultKeyName: "example-encryption",
	}
}

// TransitClient provides encryption and decryption using Vault's Transit engine.
type TransitClient struct {
	vaultClient *Client
	config      TransitConfig
}

// NewTransitClient creates a new Transit client.
func NewTransitClient(vaultClient *Client, cfg TransitConfig) (*TransitClient, error) {
	if vaultClient == nil {
		return nil, fmt.Errorf("vault client is required")
	}

	return &TransitClient{
		vaultClient: vaultClient,
		config:      cfg,
	}, nil
}

// Encrypt encrypts plaintext using the specified key (or default key).
// Returns the ciphertext in Vault's format: "vault:v1:..."
func (t *TransitClient) Encrypt(ctx context.Context, plaintext []byte, keyName ...string) (string, error) {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return "", fmt.Errorf("Transit encryption is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	// Vault Transit expects base64-encoded plaintext
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)

	path := fmt.Sprintf("%s/encrypt/%s", t.config.MountPath, key)
	data := map[string]interface{}{
		"plaintext": encodedPlaintext,
	}

	secret, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("Transit encryption failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty encryption response from Vault")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext response")
	}

	return ciphertext, nil
}

// EncryptString encrypts a string using the specified key (or default key).
func (t *TransitClient) EncryptString(ctx context.Context, plaintext string, keyName ...string) (string, error) {
	return t.Encrypt(ctx, []byte(plaintext), keyName...)
}

// Decrypt decrypts ciphertext using the specified key (or default key).
// Expects ciphertext in Vault's format: "vault:v1:..."
func (t *TransitClient) Decrypt(ctx context.Context, ciphertext string, keyName ...string) ([]byte, error) {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return nil, fmt.Errorf("Transit encryption is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	path := fmt.Sprintf("%s/decrypt/%s", t.config.MountPath, key)
	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	secret, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("Transit decryption failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty decryption response from Vault")
	}

	encodedPlaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid plaintext response")
	}

	// Vault returns base64-encoded plaintext
	plaintext, err := base64.StdEncoding.DecodeString(encodedPlaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// DecryptString decrypts ciphertext to a string.
func (t *TransitClient) DecryptString(ctx context.Context, ciphertext string, keyName ...string) (string, error) {
	plaintext, err := t.Decrypt(ctx, ciphertext, keyName...)
	if err != nil {
		return "", fmt.Errorf("DecryptString: Decrypt failed: %w", err)
	}
	return string(plaintext), nil
}

// Rewrap re-encrypts ciphertext with the latest version of the key.
// This is useful for key rotation without decrypting the data.
func (t *TransitClient) Rewrap(ctx context.Context, ciphertext string, keyName ...string) (string, error) {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return "", fmt.Errorf("Transit encryption is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	path := fmt.Sprintf("%s/rewrap/%s", t.config.MountPath, key)
	data := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	secret, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("Transit rewrap failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty rewrap response from Vault")
	}

	newCiphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext response")
	}

	return newCiphertext, nil
}

// DataKey holds both the plaintext key (for use) and the encrypted key (for storage).
// Use GenerateDataKey to create a new key encrypted with the Transit key.
type DataKey struct {
	Plaintext  []byte
	Ciphertext string
}

// GenerateDataKey generates a new data key.
func (t *TransitClient) GenerateDataKey(ctx context.Context, keyName ...string) (*DataKey, error) {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return nil, fmt.Errorf("Transit encryption is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	path := fmt.Sprintf("%s/datakey/plaintext/%s", t.config.MountPath, key)
	data := map[string]interface{}{
		"bits": 256,
	}

	secret, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty data key response from Vault")
	}

	encodedPlaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid plaintext in data key response")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid ciphertext in data key response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(encodedPlaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data key plaintext: %w", err)
	}

	return &DataKey{
		Plaintext:  plaintext,
		Ciphertext: ciphertext,
	}, nil
}

// Sign signs data using the specified key.
// Returns the signature in Vault's format.
func (t *TransitClient) Sign(ctx context.Context, data []byte, keyName ...string) (string, error) {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return "", fmt.Errorf("Transit signing is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	// Hash the input data
	encodedInput := base64.StdEncoding.EncodeToString(data)

	path := fmt.Sprintf("%s/sign/%s", t.config.MountPath, key)
	requestData := map[string]interface{}{
		"input":               encodedInput,
		"hash_algorithm":      "sha2-256",
		"signature_algorithm": "pkcs1v15",
		"prehashed":           false,
	}

	secret, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		return "", fmt.Errorf("Transit signing failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty signing response from Vault")
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("invalid signature response")
	}

	return signature, nil
}

// Verify verifies a signature.
func (t *TransitClient) Verify(ctx context.Context, data []byte, signature string, keyName ...string) (bool, error) {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return false, fmt.Errorf("Transit verification is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	encodedInput := base64.StdEncoding.EncodeToString(data)

	path := fmt.Sprintf("%s/verify/%s", t.config.MountPath, key)
	requestData := map[string]interface{}{
		"input":          encodedInput,
		"signature":      signature,
		"hash_algorithm": "sha2-256",
	}

	secret, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		return false, fmt.Errorf("Transit verification failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return false, fmt.Errorf("empty verification response from Vault")
	}

	valid, ok := secret.Data["valid"].(bool)
	if !ok {
		return false, fmt.Errorf("invalid verification response")
	}

	return valid, nil
}

// IsEnabled returns whether Transit encryption is enabled.
func (t *TransitClient) IsEnabled() bool {
	return t.config.Enabled && t.vaultClient.IsEnabled()
}

// RotateKey triggers a key rotation for the specified key.
func (t *TransitClient) RotateKey(ctx context.Context, keyName ...string) error {
	if !t.config.Enabled || !t.vaultClient.IsEnabled() {
		return fmt.Errorf("Transit encryption is not enabled")
	}

	key := t.config.DefaultKeyName
	if len(keyName) > 0 && keyName[0] != "" {
		key = keyName[0]
	}

	path := fmt.Sprintf("%s/keys/%s/rotate", t.config.MountPath, key)

	_, err := t.vaultClient.client.Logical().WriteWithContext(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("key rotation failed: %w", err)
	}

	return nil
}
