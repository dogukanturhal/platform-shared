// SPDX-License-Identifier: Apache-2.0

package falconauthz_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dogukanturhal/platform-shared/auth"
	"github.com/dogukanturhal/platform-shared/auth/falconauthz"
)

const secret = "test-secret-key-for-jwt-signing-32chars" // gitleaks:allow

type stub struct {
	mu      sync.Mutex
	calls   int
	bearers []string
	tenants []string
	bodies  []map[string]any
	allow   map[string]bool
	status  int
}

func (s *stub) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.bearers = append(s.bearers, r.Header.Get("Authorization"))
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.bodies = append(s.bodies, body)
	s.tenants = append(s.tenants, r.Header.Get("X-Tenant-ID"))
	if r.URL.Path != "/api/v1/authorize/batch" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// Mirrors falcon-id's tenant middleware, which rejects /api/v1 calls
	// without X-Tenant-ID before the handler runs.
	if r.Header.Get("X-Tenant-ID") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	res := map[string]bool{}
	for _, p := range body["permissions"].([]any) {
		res[p.(string)] = s.allow[p.(string)]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
}

func token(t *testing.T) (string, uuid.UUID, uuid.UUID) {
	uid, tid := uuid.New(), uuid.New()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "hexxlock-iam", "sub": uid.String(), "user_id": uid.String(), "tenant_id": tid.String(),
		"session_id": uuid.New().String(), "iat": time.Now().Unix(), "nbf": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"aud": []string{auth.LegacyServiceMeshAudience, auth.PlatformAPIAudience},
	}).SignedString([]byte(secret))
	require.NoError(t, err)
	return s, uid, tid
}

func setup(t *testing.T, st *stub) (*gin.Engine, *falconauthz.Checker) {
	srv := httptest.NewServer(http.HandlerFunc(st.handler))
	t.Cleanup(srv.Close)
	c, err := falconauthz.New(falconauthz.Config{BaseURL: srv.URL})
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	m := auth.NewMiddleware(&auth.Config{JWTSecret: secret, JWTIssuer: "hexxlock-iam", PermissionChecker: c})
	r := gin.New()
	r.GET("/x", m.RequireAuth(), m.RequirePermission("platform:admin", "core:billing:read"), func(c *gin.Context) { c.String(200, "ok") })
	return r, c
}

func get(r *gin.Engine, tok string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestForwardsBearerAndBodyAndSkipsTwoPart(t *testing.T) {
	st := &stub{allow: map[string]bool{"core:billing:read": true}}
	r, _ := setup(t, st)
	tok, uid, tid := token(t)

	assert.Equal(t, 200, get(r, tok).Code)
	require.Equal(t, 1, st.calls)
	assert.Equal(t, "Bearer "+tok, st.bearers[0])
	assert.Equal(t, uid.String(), st.bodies[0]["userId"])
	assert.Equal(t, tid.String(), st.bodies[0]["tenantId"])
	assert.Equal(t, tid.String(), st.tenants[0])
	assert.Equal(t, []any{"core:billing:read"}, st.bodies[0]["permissions"])
}

func TestDenyAndUpstreamError(t *testing.T) {
	st := &stub{allow: map[string]bool{}}
	r, _ := setup(t, st)
	tok, _, _ := token(t)
	assert.Equal(t, 403, get(r, tok).Code)

	st2 := &stub{status: 500}
	r2, _ := setup(t, st2)
	w := get(r2, tok)
	assert.Equal(t, 503, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_PERMISSION_UNAVAILABLE")
}

func TestOnlyTwoPartPermissionsMakeNoCall(t *testing.T) {
	st := &stub{}
	_, c := setup(t, st)
	res, err := c.CheckPermissions(t.Context(), auth.PermissionQuery{Bearer: "x", Permissions: []string{"platform:admin", "a:b", "a::c"}})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, st.calls)
}

func TestCacheKeyedPerToken(t *testing.T) {
	st := &stub{allow: map[string]bool{"core:billing:read": true}}
	r, _ := setup(t, st)
	tokA, _, _ := token(t)
	tokB, _, _ := token(t)

	get(r, tokA)
	get(r, tokA)
	assert.Equal(t, 1, st.calls, "same token is cached")
	get(r, tokB)
	assert.Equal(t, 2, st.calls, "other token is not served from cache")
}

func TestCacheExpiresAndIsBounded(t *testing.T) {
	st := &stub{allow: map[string]bool{"a:b:c": true}}
	srv := httptest.NewServer(http.HandlerFunc(st.handler))
	defer srv.Close()
	c, err := falconauthz.New(falconauthz.Config{BaseURL: srv.URL, CacheTTL: 20 * time.Millisecond, MaxEntries: 2})
	require.NoError(t, err)
	q := auth.PermissionQuery{UserID: uuid.New(), TenantID: uuid.New(), Bearer: "t1", Permissions: []string{"a:b:c"}}
	_, _ = c.CheckPermissions(t.Context(), q)
	time.Sleep(40 * time.Millisecond)
	_, _ = c.CheckPermissions(t.Context(), q)
	assert.Equal(t, 2, st.calls)
	for _, b := range []string{"t2", "t3", "t4"} {
		q.Bearer = b
		_, err := c.CheckPermissions(t.Context(), q)
		require.NoError(t, err)
	}
}

func TestNewFromEnvUnset(t *testing.T) {
	t.Setenv(falconauthz.EnvResolverURL, "")
	c, err := falconauthz.NewFromEnv()
	require.NoError(t, err)
	assert.Nil(t, c)
}
