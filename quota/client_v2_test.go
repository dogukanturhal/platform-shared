// SPDX-License-Identifier: Apache-2.0

package quota

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func registryJSON(failMode string) string {
	return `{"success":true,"data":[{"key":"workflows","kind":"metered","unit":"count","meter_class":"stock","fail_mode":"` + failMode + `","aliases":["wf"]}]}`
}

func TestReserveConfirmSendsIdemKeyAndSourceRef(t *testing.T) {
	var reserveBody, confirmBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 512)
		n, _ := r.Body.Read(b)
		switch r.URL.Path {
		case "/api/v1/quota/reserve":
			reserveBody = string(b[:n])
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":"r1","replayed":true}}`))
		case "/api/v1/quota/reservations/r1/confirm":
			confirmBody = string(b[:n])
			_, _ = w.Write([]byte(`{"success":true}`))
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	h, err := c.Reserve(context.Background(), uuid.New(), "workflows", 1, "wf:1:activate")
	if err != nil || h.ID != "r1" || !h.Replayed {
		t.Fatalf("hold=%+v err=%v", h, err)
	}
	if !strings.Contains(reserveBody, `"idempotency_key":"wf:1:activate"`) {
		t.Fatalf("reserve body %s", reserveBody)
	}
	if err := h.Confirm(context.Background(), "wf:1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(confirmBody, `"source_ref":"wf:1"`) {
		t.Fatalf("confirm body %s", confirmBody)
	}
}

func TestReserveRefusals(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		check  func(error) bool
	}{
		"409 exceeded": {409, `{"code":"quota_exceeded","limit":5,"usage":5,"requested":1,"enforcement":"block"}`, func(e error) bool {
			var q *QuotaExceededError
			return errors.As(e, &q) && q.Limit == 5 && q.Enforcement == "block"
		}},
		"legacy 403":  {403, `{"success":false,"error":{"code":"FORBIDDEN","message":"Quota exceeded"}}`, IsQuotaExceededError},
		"idempotency": {409, `{"code":"idempotency_conflict"}`, func(e error) bool { return errors.Is(e, ErrIdempotencyConflict) }},
		"auth 403": {403, `{"success":false,"error":{"message":"insufficient permissions"}}`, func(e error) bool {
			return e != nil && !IsQuotaExceededError(e) && !errors.Is(e, ErrQuotaUnavailable)
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := NewClient(srv.URL, nil).Reserve(context.Background(), uuid.New(), "workflows", 1, "k")
			if !tc.check(err) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestReserveFailModeFromRegistry(t *testing.T) {
	for mode, wantOpen := range map[string]bool{"open": true, "closed": false} {
		var down atomic.Bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/internal/v1/quota/registry" {
				_, _ = w.Write([]byte(registryJSON(mode)))
				return
			}
			down.Store(true)
			w.WriteHeader(http.StatusBadGateway)
		}))
		c := NewClient(srv.URL, nil)
		h, err := c.Reserve(context.Background(), uuid.New(), "wf", 1, "k") // alias resolves
		srv.Close()
		if wantOpen && (err != nil || !h.Noop()) {
			t.Fatalf("%s: want no-op hold, got %+v %v", mode, h, err)
		}
		if !wantOpen && !errors.Is(err, ErrQuotaUnavailable) {
			t.Fatalf("%s: want unavailable, got %v", mode, err)
		}
	}
}

func TestReturnAndRecount(t *testing.T) {
	var paths, tenantHdr []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		tenantHdr = append(tenantHdr, r.Header.Get("X-Tenant-ID"))
		_, _ = w.Write([]byte(`{"success":true,"data":{"results":[{"resource_type":"workflows","status":"corrected","recorded":3,"actual":2,"drift":-1}]}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	tenant := uuid.New()
	if err := c.Return(context.Background(), tenant, "workflows", 1, "wf:1"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Recount(context.Background(), tenant, []RecountItem{{Key: "workflows", Count: 2}})
	if err != nil || len(res) != 1 || res[0].Status != "corrected" {
		t.Fatalf("%+v %v", res, err)
	}
	if paths[1] != "/internal/v1/usage/recount" || tenantHdr[1] != tenant.String() {
		t.Fatalf("paths=%v hdr=%v", paths, tenantHdr)
	}
}

func TestRegistryAssert(t *testing.T) {
	r := newRegistry([]RegistryEntry{{Key: "workflows", Kind: "metered", Unit: "count"}}, time.Now())
	if got := r.Assert(Expected{Key: "workflows", Kind: "metered"}); len(got) != 0 {
		t.Fatal(got)
	}
	if got := r.Assert(Expected{Key: "nope"}, Expected{Key: "workflows", Unit: "bytes"}); len(got) != 2 {
		t.Fatal(got)
	}
}

type fakeProvider struct{}

func (fakeProvider) Keys() []string { return []string{"workflows"} }
func (fakeProvider) Count(context.Context, uuid.UUID, string, *time.Time) (int64, error) {
	return 4, nil
}

func TestCountsHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/c", CountsHandler(fakeProvider{}, nil))
	tenant := uuid.New()
	do := func(hdr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/c", strings.NewReader(`{"tenant_id":"`+tenant.String()+`","resource_types":["workflows","x"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", hdr)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	if w := do(uuid.NewString()); w.Code != 403 {
		t.Fatalf("mismatch tenant: %d", w.Code)
	}
	w := do(tenant.String())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"value":4`) || !strings.Contains(w.Body.String(), `"unknown":["x"]`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
