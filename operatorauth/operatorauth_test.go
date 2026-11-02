// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testIssuer = "https://id.test"

type testIdP struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	return &testIdP{key: key, srv: srv}
}

func (i *testIdP) token(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": testIssuer, "aud": []string{Audience}, "sub": uuid.NewString(),
		"tid": InternalTenantID, "tenant_id": InternalTenantID, "gty": "operator_exchange",
		"platform_roles": []string{"platform_viewer"}, "ops_perms": []string{"ops:tenants:read"},
		"amr": []string{"pwd", "otp"}, "auth_time": time.Now().Unix(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (i *testIdP) verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{JWKSURL: i.srv.URL, Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func serve(h gin.HandlerFunc, token string, mw ...gin.HandlerFunc) int {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", append(mw, h)...)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if token != "" {
		req.Header.Set(HeaderActorAssertion, "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func ok(c *gin.Context) { c.Status(http.StatusOK) }

func TestRequireOperator(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.verifier(t)

	if got := serve(ok, idp.token(t, nil), v.RequireOperator("ops:tenants:read")); got != http.StatusOK {
		t.Fatalf("valid assertion with permission: got %d", got)
	}
	if got := serve(ok, idp.token(t, nil), v.RequireOperator("ops:tenants:purge")); got != http.StatusForbidden {
		t.Fatalf("missing permission must be 403, got %d", got)
	}
	if got := serve(ok, "", v.RequireOperator("ops:tenants:read")); got != http.StatusUnauthorized {
		t.Fatalf("no assertion must be 401, got %d", got)
	}
	// A normal access token (other audience, standing roles claim) is refused.
	legacy := idp.token(t, func(c jwt.MapClaims) {
		c["aud"] = []string{"https://api.example.com"}
		c["roles"] = []string{"platform_admin"}
		delete(c, "gty")
	})
	if got := serve(ok, legacy, v.RequireOperator("ops:tenants:read")); got != http.StatusUnauthorized {
		t.Fatalf("legacy access token must be 401, got %d", got)
	}
	notInternal := idp.token(t, func(c jwt.MapClaims) {
		c["tid"] = uuid.NewString()
		c["tenant_id"] = c["tid"]
	})
	if got := serve(ok, notInternal, v.RequireOperator("ops:tenants:read")); got != http.StatusForbidden {
		t.Fatalf("non-internal tenant must be 403, got %d", got)
	}
	expired := idp.token(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	if got := serve(ok, expired, v.RequireOperator("ops:tenants:read")); got != http.StatusUnauthorized {
		t.Fatalf("expired assertion must be 401, got %d", got)
	}
}

func TestRequireStepUp(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.verifier(t)
	chain := func(tok string) int {
		return serve(ok, tok, v.RequireOperator("ops:tenants:read"), RequireStepUp(5*time.Minute))
	}
	if got := chain(idp.token(t, nil)); got != http.StatusOK {
		t.Fatalf("fresh MFA: got %d", got)
	}
	stale := idp.token(t, func(c jwt.MapClaims) { c["auth_time"] = time.Now().Add(-time.Hour).Unix() })
	if got := chain(stale); got != http.StatusUnauthorized {
		t.Fatalf("stale auth_time must be 401, got %d", got)
	}
	noMFA := idp.token(t, func(c jwt.MapClaims) { c["amr"] = []string{"pwd"} })
	if got := chain(noMFA); got != http.StatusUnauthorized {
		t.Fatalf("password-only must be 401, got %d", got)
	}
}

func TestRequireApprovalFailsClosed(t *testing.T) {
	SetApprovalChecker(nil)
	if got := serve(ok, "", RequireApproval("tenant.purge.apply")); got != http.StatusForbidden {
		t.Fatalf("RequireApproval without a checker must be 403, got %d", got)
	}
}

func TestParseReason(t *testing.T) {
	if _, err := ParseReason("support_ticket", "customer asked us to extend the trial"); err != nil {
		t.Fatalf("valid reason rejected: %v", err)
	}
	if _, err := ParseReason("nope", "customer asked us to extend the trial"); err == nil {
		t.Fatal("unknown code accepted")
	}
	if _, err := ParseReason("support_ticket", "too short"); err == nil {
		t.Fatal("short justification accepted")
	}
}

func standingActorMW(standing bool, email string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(CtxKeyActor, &Actor{
			Email: email, TenantID: InternalTenantID,
			PlatformRoles: []string{"platform_admin"}, StandingPlatformAdmin: standing,
		})
		c.Next()
	}
}

// directEcho runs DirectReason and echoes the body the handler sees.
func directEcho(loc ReasonLocation, standing bool, body string, hdr map[string]string) (int, string, http.Header) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var seenHdr http.Header
	r.POST("/x", standingActorMW(standing, "root@example.com"), DirectReason(loc), func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		seenHdr = c.Request.Header.Clone()
		if int64(len(b)) != c.Request.ContentLength && c.Request.ContentLength >= 0 && len(b) > 0 {
			c.String(http.StatusInternalServerError, "content-length mismatch")
			return
		}
		c.String(http.StatusOK, string(b))
	})
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String(), seenHdr
}

func TestIsStandingPlatformAdmin(t *testing.T) {
	a := &Actor{StandingPlatformAdmin: true, TenantID: InternalTenantID, PlatformRoles: []string{"platform_admin"}}
	if !a.IsStandingPlatformAdmin() {
		t.Fatal("standing admin not recognised")
	}
	for name, b := range map[string]*Actor{
		"nil":      nil,
		"no flag":  {TenantID: InternalTenantID, PlatformRoles: []string{"platform_admin"}},
		"viewer":   {StandingPlatformAdmin: true, TenantID: InternalTenantID, PlatformRoles: []string{"platform_viewer"}},
		"external": {StandingPlatformAdmin: true, TenantID: uuid.NewString(), PlatformRoles: []string{"platform_admin"}},
	} {
		if b.IsStandingPlatformAdmin() {
			t.Fatalf("%s must not be standing", name)
		}
	}
}

func TestVerifierMapsStandingClaim(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.verifier(t)
	a, err := v.Verify(context.Background(), idp.token(t, func(c jwt.MapClaims) { c["standing_platform_admin"] = true }))
	if err != nil || !a.StandingPlatformAdmin {
		t.Fatalf("claim not mapped: %v %+v", err, a)
	}
	a, err = v.Verify(context.Background(), idp.token(t, nil))
	if err != nil || a.StandingPlatformAdmin {
		t.Fatalf("absent claim must be false: %v", err)
	}
}

func TestReasonPlatformAdmin(t *testing.T) {
	if !ReasonPlatformAdmin.Valid() {
		t.Fatal("platform_admin must be Valid")
	}
	for _, k := range ReasonCodes() {
		if k == ReasonPlatformAdmin {
			t.Fatal("platform_admin must not be listed")
		}
	}
	if len(PlatformAdminReasonText("")) < 32 || len(PlatformAdminReasonText("a@b.c")) < 32 {
		t.Fatal("canonical text too short")
	}
}

func TestDirectReasonBody(t *testing.T) {
	code, body, _ := directEcho(ReasonInBody, true, `{"x":1}`, nil)
	if code != 200 || !strings.Contains(body, `"reason_code":"platform_admin"`) ||
		!strings.Contains(body, "platform_admin direct action by root@example.com") || !strings.Contains(body, `"x":1`) {
		t.Fatalf("standing inject: %d %s", code, body)
	}
	code, body, _ = directEcho(ReasonInBody, true, ``, nil)
	if code != 200 || !strings.Contains(body, `"reason_code":"platform_admin"`) {
		t.Fatalf("standing empty body: %d %s", code, body)
	}
	code, body, _ = directEcho(ReasonInBody, true, `{"reason_code":"other"}`, nil)
	if code != 200 || !strings.Contains(body, `"reason_code":"other"`) || !strings.Contains(body, "direct action by") {
		t.Fatalf("code given, text filled: %d %s", code, body)
	}
	in := `{"reason_code":"other","reason":"a supplied justification text"}`
	if code, body, _ = directEcho(ReasonInBody, true, in, nil); code != 200 || body != in {
		t.Fatalf("supplied reason must be untouched: %d %s", code, body)
	}
	if code, body, _ = directEcho(ReasonInBody, true, `[1,2]`, nil); code != 200 || body != `[1,2]` {
		t.Fatalf("non-object must pass through: %d %s", code, body)
	}
	if code, _, _ = directEcho(ReasonInBody, false, `{"reason_code":"platform_admin"}`, nil); code != 400 {
		t.Fatalf("reserved code for non-standing must be 400, got %d", code)
	}
	if code, body, _ = directEcho(ReasonInBody, false, `{"x":1}`, nil); code != 200 || body != `{"x":1}` {
		t.Fatalf("non-standing body untouched: %d %s", code, body)
	}
	big := `{"pad":"` + strings.Repeat("a", maxDirectBody) + `"}`
	if code, body, _ = directEcho(ReasonInBody, true, big, nil); code != 200 || body != big {
		t.Fatalf("oversize must pass through for standing: %d", code)
	}
}

func TestDirectReasonHeaders(t *testing.T) {
	code, _, h := directEcho(ReasonInHeaders, true, ``, nil)
	if code != 200 || h.Get(HeaderReasonCode) != "platform_admin" || len(h.Get(HeaderReason)) < 32 {
		t.Fatalf("standing header inject: %d %v", code, h)
	}
	code, _, h = directEcho(ReasonInHeaders, true, ``, map[string]string{HeaderReason: "my own justification text here"})
	if code != 200 || h.Get(HeaderReason) != "my own justification text here" || h.Get(HeaderReasonCode) != "" {
		t.Fatalf("supplied reason untouched: %d %v", code, h)
	}
	if code, _, _ = directEcho(ReasonInHeaders, false, ``, map[string]string{HeaderReasonCode: "platform_admin"}); code != 400 {
		t.Fatalf("reserved header code for non-standing must be 400, got %d", code)
	}
}

type fakeChecker struct{ err error }

func (f fakeChecker) Consume(*gin.Context, string) error { return f.err }

func TestRequireApprovalStandingBypass(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(standing bool) (int, string) {
		r := gin.New()
		mode := ""
		r.GET("/x", standingActorMW(standing, "r@h.com"), RequireApproval("a.b"), func(c *gin.Context) {
			mode = ApprovalModeFrom(c)
			c.Status(http.StatusOK)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		return w.Code, mode
	}
	SetApprovalChecker(nil)
	if code, _ := run(true); code != http.StatusForbidden {
		t.Fatalf("no checker must refuse even standing, got %d", code)
	}
	SetApprovalChecker(fakeChecker{err: errors.New("no approval")})
	t.Cleanup(func() { SetApprovalChecker(nil) })
	if code, mode := run(true); code != 200 || mode != ApprovalModePlatformAdminBypass {
		t.Fatalf("standing bypass: %d %q", code, mode)
	}
	if code, _ := run(false); code != http.StatusForbidden {
		t.Fatalf("non-standing without approval must be 403, got %d", code)
	}
	SetApprovalChecker(fakeChecker{})
	if code, mode := run(false); code != 200 || mode != ApprovalModeFourEyes {
		t.Fatalf("four-eyes mode: %d %q", code, mode)
	}
}
