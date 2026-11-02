// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeChecker struct {
	calls   int
	last    PermissionQuery
	allowed map[string]bool
	err     error
}

func (f *fakeChecker) CheckPermissions(_ context.Context, q PermissionQuery) (map[string]bool, error) {
	f.calls++
	f.last = q
	return f.allowed, f.err
}

func mintToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	base := jwt.MapClaims{
		"iss":        "hexxlock-iam",
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(time.Hour).Unix(),
		"nbf":        time.Now().Unix(),
		"session_id": uuid.New().String(),
		"tenant_id":  uuid.New().String(),
		"aud":        []string{LegacyServiceMeshAudience, PlatformAPIAudience},
	}
	for k, v := range claims {
		base[k] = v
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, base).SignedString([]byte(testSecret))
	require.NoError(t, err)
	return s
}

func userToken(t *testing.T, perms []string) string {
	uid := uuid.New().String()
	c := jwt.MapClaims{"sub": uid, "user_id": uid, "roles": []string{"owner"}}
	if perms != nil {
		c["permissions"] = perms
	}
	return mintToken(t, c)
}

func serviceToken(t *testing.T) string {
	return mintToken(t, jwt.MapClaims{"sub": "svc-x", "client_id": "svc-x", "scope": "openid"})
}

func serve(t *testing.T, checker PermissionChecker, token string, gate func(m *Middleware) gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	m := NewMiddleware(&Config{JWTSecret: testSecret, JWTIssuer: "hexxlock-iam", PermissionChecker: checker})
	r := gin.New()
	r.GET("/x", m.RequireAuth(), gate(m), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func anyOf(p ...string) func(m *Middleware) gin.HandlerFunc {
	return func(m *Middleware) gin.HandlerFunc { return m.RequirePermission(p...) }
}

func allOf(p ...string) func(m *Middleware) gin.HandlerFunc {
	return func(m *Middleware) gin.HandlerFunc { return m.RequireAllPermissions(p...) }
}

func TestPermissionChecker_ClaimPresentSkipsResolver(t *testing.T) {
	f := &fakeChecker{}
	w := serve(t, f, userToken(t, []string{"core:billing:read"}), anyOf("core:billing:read"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Zero(t, f.calls)
}

func TestPermissionChecker_AllowDenyError(t *testing.T) {
	tok := userToken(t, nil)

	f := &fakeChecker{allowed: map[string]bool{"core:billing:read": true}}
	w := serve(t, f, tok, anyOf("core:billing:read"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, f.calls)
	assert.Equal(t, tok, f.last.Bearer)
	assert.NotEqual(t, uuid.Nil, f.last.UserID)

	f = &fakeChecker{allowed: map[string]bool{"core:billing:read": false}}
	w = serve(t, f, tok, anyOf("core:billing:read"))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_PERMISSION_DENIED")

	f = &fakeChecker{err: errors.New("boom")}
	w = serve(t, f, tok, anyOf("core:billing:read"))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_PERMISSION_UNAVAILABLE")
	assert.NotContains(t, w.Body.String(), tok)
}

func TestPermissionChecker_AnyVsAllSemantics(t *testing.T) {
	tok := userToken(t, nil)
	f := &fakeChecker{allowed: map[string]bool{"a:b:c": true}}
	assert.Equal(t, http.StatusOK, serve(t, f, tok, anyOf("platform:admin", "a:b:c")).Code)
	assert.Equal(t, http.StatusForbidden, serve(t, f, tok, allOf("a:b:c", "d:e:f")).Code)
	f = &fakeChecker{allowed: map[string]bool{"a:b:c": true, "d:e:f": true}}
	assert.Equal(t, http.StatusOK, serve(t, f, tok, allOf("a:b:c", "d:e:f")).Code)
}

func TestPermissionChecker_ServiceTokenNeverCallsResolver(t *testing.T) {
	f := &fakeChecker{allowed: map[string]bool{"core:billing:read": true}}
	w := serve(t, f, serviceToken(t), anyOf("core:billing:read"))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, f.calls)
}

func TestPermissionChecker_NilCheckerKeepsOldBehaviour(t *testing.T) {
	assert.Equal(t, http.StatusForbidden, serve(t, nil, userToken(t, nil), anyOf("core:billing:read")).Code)
	assert.Equal(t, http.StatusOK, serve(t, nil, userToken(t, []string{"core:billing:read"}), anyOf("core:billing:read")).Code)
}
