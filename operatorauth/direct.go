// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// HeaderReasonCode / HeaderReason are the headers the operator services
	// already read the reason from (header-mode routes).
	HeaderReasonCode = "X-Ops-Reason-Code"
	HeaderReason     = "X-Ops-Reason"

	// maxDirectBody caps the body DirectReason will buffer and rewrite.
	maxDirectBody = 1 << 20
)

// ReasonLocation says where a route reads its reason from.
type ReasonLocation int

const (
	// ReasonInBody: top-level JSON fields reason_code and reason.
	ReasonInBody ReasonLocation = iota
	// ReasonInHeaders: HeaderReasonCode and HeaderReason.
	ReasonInHeaders
)

// DirectReason mounts AFTER RequireOperator and BEFORE the route's own reason
// validation.
//
//   - reason_code "platform_admin" from anyone but the standing platform_admin
//     => 400 reason_code_reserved.
//   - standing platform_admin with no code and no reason => code
//     "platform_admin" + PlatformAdminReasonText are injected.
//   - standing platform_admin with a code but no reason => text is filled.
//   - a supplied reason is never overwritten.
//
// Body mode only rewrites an empty body or a top-level JSON object of at most
// 1 MiB (Body and ContentLength are restored); anything else passes through.
func DirectReason(loc ReasonLocation) gin.HandlerFunc {
	return func(c *gin.Context) {
		if m := c.Request.Method; m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions {
			c.Next()
			return
		}
		actor := ActorFrom(c)
		standing := actor.IsStandingPlatformAdmin()
		if loc == ReasonInHeaders {
			directHeaders(c, actor, standing)
		} else {
			directBody(c, actor, standing)
		}
		if !c.IsAborted() {
			c.Next()
		}
	}
}

func reservedReject(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "reason_code_reserved"})
}

func directHeaders(c *gin.Context, actor *Actor, standing bool) {
	code := strings.TrimSpace(c.GetHeader(HeaderReasonCode))
	text := strings.TrimSpace(c.GetHeader(HeaderReason))
	if ReasonCode(code) == ReasonPlatformAdmin && !standing {
		reservedReject(c)
		return
	}
	if !standing {
		return
	}
	if code == "" && text == "" {
		c.Request.Header.Set(HeaderReasonCode, string(ReasonPlatformAdmin))
		code = string(ReasonPlatformAdmin)
	}
	if text == "" && code != "" {
		c.Request.Header.Set(HeaderReason, PlatformAdminReasonText(actor.Email))
	}
}

func directBody(c *gin.Context, actor *Actor, standing bool) {
	orig := c.Request.Body
	if orig == nil || orig == http.NoBody {
		if standing {
			setBody(c, nil, map[string]json.RawMessage{}, actor)
		}
		return
	}
	buf, err := io.ReadAll(io.LimitReader(orig, maxDirectBody+1))
	if err != nil || len(buf) > maxDirectBody {
		// Unreadable or oversize: hand the downstream handler what we read
		// plus the rest, untouched. The reserved-code check is skipped; the
		// worst a forged code can do there is mislabel the audit row.
		c.Request.Body = readCloser{io.MultiReader(bytes.NewReader(buf), orig), orig}
		return
	}
	_ = orig.Close()
	restore := func(b []byte) {
		c.Request.Body = io.NopCloser(bytes.NewReader(b))
		c.Request.ContentLength = int64(len(b))
	}
	trimmed := bytes.TrimSpace(buf)
	if len(trimmed) == 0 {
		if standing {
			setBody(c, nil, map[string]json.RawMessage{}, actor)
		} else {
			restore(buf)
		}
		return
	}
	var obj map[string]json.RawMessage
	if trimmed[0] != '{' || json.Unmarshal(trimmed, &obj) != nil || obj == nil {
		restore(buf) // not a top-level object: pass through
		return
	}
	code, codeOK := rawString(obj["reason_code"])
	text, textOK := rawString(obj["reason"])
	if _, present := obj["reason_code"]; present && !codeOK {
		restore(buf)
		return
	}
	if _, present := obj["reason"]; present && !textOK {
		restore(buf)
		return
	}
	code, text = strings.TrimSpace(code), strings.TrimSpace(text)
	if ReasonCode(code) == ReasonPlatformAdmin && !standing {
		restore(buf)
		reservedReject(c)
		return
	}
	if !standing {
		restore(buf)
		return
	}
	changed := false
	if code == "" && text == "" {
		obj["reason_code"] = mustJSON(string(ReasonPlatformAdmin))
		code, changed = string(ReasonPlatformAdmin), true
	}
	if text == "" && code != "" {
		obj["reason"] = mustJSON(PlatformAdminReasonText(actor.Email))
		changed = true
	}
	if !changed {
		restore(buf)
		return
	}
	setBody(c, buf, obj, actor)
}

// setBody serialises obj as the request body. On failure it restores orig.
func setBody(c *gin.Context, orig []byte, obj map[string]json.RawMessage, actor *Actor) {
	if len(obj) == 0 {
		obj["reason_code"] = mustJSON(string(ReasonPlatformAdmin))
		obj["reason"] = mustJSON(PlatformAdminReasonText(actor.Email))
	}
	b, err := json.Marshal(obj)
	if err != nil {
		b = orig
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(b))
	c.Request.ContentLength = int64(len(b))
	if c.Request.Header.Get("Content-Type") == "" {
		c.Request.Header.Set("Content-Type", "application/json")
	}
	c.Request.Header.Set("Content-Length", strconv.Itoa(len(b)))
}

type readCloser struct {
	io.Reader
	io.Closer
}

func rawString(r json.RawMessage) (string, bool) {
	if len(r) == 0 {
		return "", true
	}
	var s string
	if json.Unmarshal(r, &s) != nil {
		return "", false
	}
	return s, true
}

func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
