// SPDX-License-Identifier: Apache-2.0

package serviceauth

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// newObservedLogger returns a zap.Logger backed by an in-memory observer so
// tests can assert on emitted log entries without touching stdout/files.
func newObservedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.WarnLevel)
	return zap.New(core), logs
}

// ---------------------------------------------------------------------------
// RequireScopeAudit
// ---------------------------------------------------------------------------

func TestRequireScopeAudit_GrantedScope_NoLogAndNextReached(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObservedLogger()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyClientID, "svc-billing")
		c.Set(ContextKeyScope, "platform:tenants:read service:register")
		c.Next()
	})
	nextReached := false
	r.GET("/tenants",
		RequireScopeAudit("platform:tenants:read", logger),
		func(c *gin.Context) { nextReached = true; c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 (audit mode never rejects), got %d body=%q", w.Code, w.Body.String())
	}
	if !nextReached {
		t.Fatalf("expected downstream handler (c.Next) to be reached")
	}
	if logs.Len() != 0 {
		t.Fatalf("expected no WARN log for a granted scope, got %d entries: %+v", logs.Len(), logs.All())
	}
}

func TestRequireScopeAudit_MissingScope_LogsWarnButStillNexts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObservedLogger()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyClientID, "svc-billing")
		c.Set(ContextKeyScope, "service:register")
		c.Next()
	})
	nextReached := false
	r.GET("/tenants",
		RequireScopeAudit("platform:tenants:read", logger),
		func(c *gin.Context) { nextReached = true; c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)
	r.ServeHTTP(w, req)

	// Zero behavior change: still 200, same as if RequireScopeAudit were not
	// chained at all.
	if w.Code != 200 {
		t.Fatalf("expected 200 (audit mode never rejects) even on a would-be denial, got %d", w.Code)
	}
	if !nextReached {
		t.Fatalf("expected downstream handler (c.Next) to be reached")
	}

	if logs.Len() != 1 {
		t.Fatalf("expected exactly one WARN log entry for a would-be denial, got %d: %+v", logs.Len(), logs.All())
	}
	entry := logs.All()[0]
	if entry.Level != zapcore.WarnLevel {
		t.Fatalf("expected WARN level, got %v", entry.Level)
	}
	if entry.Message != ScopeAuditEvent {
		t.Fatalf("expected message %q, got %q", ScopeAuditEvent, entry.Message)
	}
	fields := entry.ContextMap()
	if fields["client_id"] != "svc-billing" {
		t.Errorf("expected client_id=svc-billing, got %v", fields["client_id"])
	}
	if fields["method"] != "GET" {
		t.Errorf("expected method=GET, got %v", fields["method"])
	}
	if fields["path"] != "/tenants" {
		t.Errorf("expected path=/tenants, got %v", fields["path"])
	}
	if fields["granted_scope"] != "service:register" {
		t.Errorf("expected granted_scope=service:register, got %v", fields["granted_scope"])
	}
	requiredScope, ok := fields["required_scope"].([]interface{})
	if !ok || len(requiredScope) != 1 || requiredScope[0] != "platform:tenants:read" {
		t.Errorf("expected required_scope=[platform:tenants:read], got %v", fields["required_scope"])
	}
}

func TestRequireScopeAudit_EmptyScopeClaim_NoPanicLogsWarn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObservedLogger()

	r := gin.New()
	// No RequireServiceAuth run at all -- scope claim entirely absent from
	// context. This is exactly the population RequireScopeAudit exists to
	// measure and must never panic or 500 on.
	r.GET("/tenants",
		RequireScopeAudit("platform:tenants:read", logger),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RequireScopeAudit panicked on missing scope claim: %v", r)
			}
		}()
		r.ServeHTTP(w, req)
	}()

	if w.Code != 200 {
		t.Fatalf("expected 200 even with no scope claim on context, got %d", w.Code)
	}
	if logs.Len() != 1 {
		t.Fatalf("expected one WARN log entry for the missing-scope-claim case, got %d", logs.Len())
	}
	fields := logs.All()[0].ContextMap()
	if fields["granted_scope"] != "" {
		t.Errorf("expected empty granted_scope, got %v", fields["granted_scope"])
	}
}

func TestRequireScopeAudit_MalformedScopeClaim_NoPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObservedLogger()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Malformed: scope claim present but not a string (e.g. a decode
		// artifact from a non-conforming token). GetScope's type assertion
		// must fail safely, not panic.
		c.Set(ContextKeyScope, 12345)
		c.Next()
	})

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RequireScopeAudit panicked on malformed scope claim: %v", r)
			}
		}()
		r.GET("/tenants",
			RequireScopeAudit("platform:tenants:read", logger),
			func(c *gin.Context) { c.String(200, "ok") },
		)
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/tenants", nil)
		r.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Fatalf("expected 200 even with a malformed scope claim, got %d", w.Code)
		}
	}()

	if logs.Len() != 1 {
		t.Fatalf("expected one WARN log entry for the malformed-scope-claim case, got %d", logs.Len())
	}
}

func TestRequireScopeAudit_NilLogger_NoPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/tenants",
		RequireScopeAudit("platform:tenants:read", nil),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RequireScopeAudit panicked with a nil logger: %v", r)
		}
	}()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 with a nil logger, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// RequireAnyScopeAudit
// ---------------------------------------------------------------------------

func TestRequireAnyScopeAudit_OneGranted_NoLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObservedLogger()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyClientID, "svc-quota")
		c.Set(ContextKeyScope, "platform:plans:read")
		c.Next()
	})
	nextReached := false
	r.GET("/plans",
		RequireAnyScopeAudit([]string{"platform:plans:read", "platform:plans:write"}, logger),
		func(c *gin.Context) { nextReached = true; c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/plans", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 || !nextReached {
		t.Fatalf("expected 200 and downstream handler reached, got code=%d nextReached=%v", w.Code, nextReached)
	}
	if logs.Len() != 0 {
		t.Fatalf("expected no WARN log when one required scope is granted, got %d", logs.Len())
	}
}

func TestRequireAnyScopeAudit_NoneGranted_LogsWarnButStillNexts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, logs := newObservedLogger()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyClientID, "svc-quota")
		c.Set(ContextKeyScope, "service:register")
		c.Next()
	})
	nextReached := false
	r.GET("/plans",
		RequireAnyScopeAudit([]string{"platform:plans:read", "platform:plans:write"}, logger),
		func(c *gin.Context) { nextReached = true; c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/plans", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 || !nextReached {
		t.Fatalf("expected 200 and downstream handler reached (audit never rejects), got code=%d nextReached=%v", w.Code, nextReached)
	}
	if logs.Len() != 1 {
		t.Fatalf("expected exactly one WARN log entry, got %d", logs.Len())
	}
	fields := logs.All()[0].ContextMap()
	requiredScope, ok := fields["required_scope"].([]interface{})
	if !ok || len(requiredScope) != 2 {
		t.Errorf("expected required_scope with both candidates, got %v", fields["required_scope"])
	}
}

// ---------------------------------------------------------------------------
// Control: RequireScope (enforcing) is untouched by this change.
// ---------------------------------------------------------------------------

// TestControl_RequireScope_StillEnforces is a control for the audit tests
// above: it asserts the pre-existing enforcing middleware still 403s under
// the exact same missing-scope condition that RequireScopeAudit only logs.
// If this test ever passes with a 200, it means RequireScope's behavior
// changed -- exactly what this MR must not do.
func TestControl_RequireScope_StillEnforces(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(ContextKeyScope, "service:register")
		c.Next()
	})
	r.GET("/tenants",
		RequireScope("platform:tenants:read"),
		func(c *gin.Context) { c.String(200, "ok") },
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/tenants", nil)
	r.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("control failed: expected RequireScope to still 403 on missing scope, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ParseScopeMode
// ---------------------------------------------------------------------------

func TestParseScopeMode(t *testing.T) {
	cases := map[string]ScopeMode{
		"enforce":   ScopeModeEnforce,
		"Enforce":   ScopeModeEnforce,
		"ENFORCE":   ScopeModeEnforce,
		" enforce ": ScopeModeEnforce,
		"audit":     ScopeModeAudit,
		"":          ScopeModeAudit,
		"bogus":     ScopeModeAudit,
	}
	for input, want := range cases {
		if got := ParseScopeMode(input); got != want {
			t.Errorf("ParseScopeMode(%q) = %q, want %q", input, got, want)
		}
	}
}
