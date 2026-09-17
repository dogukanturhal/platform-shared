// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"strings"
	"testing"
)

// v1 and v2 differ in BOTH the path and the payload shape, and getting either
// wrong fails quietly: a v2-shaped write into a v1 mount stores a literal
// "data" key wrapping the real content, which then reads back as a secret
// whose fields are all missing. Nothing errors.
func TestPutSecretKV1_RequiresMountAndPath(t *testing.T) {
	c := &Client{config: Config{Enabled: true, MountPath: "example"}}
	for name, args := range map[string][2]string{
		"no mount": {"", "example.com"},
		"no path":  {"dkim", ""},
	} {
		if err := c.PutSecretKV1(context.Background(), args[0], args[1],
			map[string]interface{}{"k": "v"}); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

func TestPutSecretKV1_RefusesEmptyPayload(t *testing.T) {
	c := &Client{config: Config{Enabled: true, MountPath: "example"}}
	err := c.PutSecretKV1(context.Background(), "dkim", "example.com", map[string]interface{}{})
	if err == nil {
		t.Fatal("empty secret accepted")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected an empty-payload refusal, got: %v", err)
	}
}

// A disabled client must fail loudly rather than silently discard the write.
func TestPutSecretKV1_DisabledClientErrors(t *testing.T) {
	c := &Client{config: Config{Enabled: false}}
	if err := c.PutSecretKV1(context.Background(), "dkim", "example.com",
		map[string]interface{}{"k": "v"}); err == nil {
		t.Fatal("write on a disabled client reported success")
	}
}
