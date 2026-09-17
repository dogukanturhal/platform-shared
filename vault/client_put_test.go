// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"strings"
	"testing"
)

// An empty write would create a KV version with no keys, which reads back as
// present-but-empty — indistinguishable from a corrupt entry for any consumer.
func TestPutSecret_RefusesEmptyPayload(t *testing.T) {
	c := &Client{config: Config{Enabled: true, MountPath: "example"}}
	err := c.PutSecret(context.Background(), "platform/mail/dkim/example.com", map[string]interface{}{})
	if err == nil {
		t.Fatal("empty secret was accepted")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected an empty-payload refusal, got: %v", err)
	}
}

// A disabled client must fail loudly rather than silently discard the write —
// a write that appears to succeed but stored nothing is the worst outcome.
func TestPutSecret_DisabledClientErrors(t *testing.T) {
	c := &Client{config: Config{Enabled: false}}
	err := c.PutSecret(context.Background(), "any/path", map[string]interface{}{"k": "v"})
	if err == nil {
		t.Fatal("write on a disabled client reported success")
	}
}
