// SPDX-License-Identifier: Apache-2.0

package operatorauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	serviceauth "github.com/dogukanturhal/platform-shared/service-auth"
)

const (
	// HeaderApprovalID carries the four-eyes approval id the operator got from
	// falcon-id POST /ops-approvals (status approved by a different operator).
	HeaderApprovalID = "X-Ops-Approval-Id"

	// ApprovalConsumeScope is the service scope a target service's client needs
	// to spend an approval.
	ApprovalConsumeScope = "platform:ops-approvals-consume"

	ctxKeyApprovalSpec = "operatorauth.approval_spec"
)

// ResourceFunc resolves the resource an approval is bound to (e.g.
// "tenant:<uuid>", "refund:<id>") from the request. An error or empty result
// fails closed.
type ResourceFunc func(c *gin.Context) (string, error)

// PayloadFunc computes the payload_sha256 an approval must carry for this
// request. Routes override it when the approval must bind more than
// action+resource (e.g. an amount).
type PayloadFunc func(c *gin.Context, action, resource string) (string, error)

// ApprovalPayloadHash is the default canonical payload hash: sha256 hex of
// "<action>:<resource>". It matches falcon-id's PayloadHash helper, so the
// console computes the same value when it requests the approval.
func ApprovalPayloadHash(action, resource string) string {
	sum := sha256.Sum256([]byte(action + ":" + resource))
	return hex.EncodeToString(sum[:])
}

// ApprovalSpec describes how one T3 route binds its approval.
type ApprovalSpec struct {
	Resource ResourceFunc
	// Payload is optional; nil uses ApprovalPayloadHash.
	Payload PayloadFunc
}

// StaticResource always resolves to r.
func StaticResource(r string) ResourceFunc {
	return func(*gin.Context) (string, error) { return r, nil }
}

// ParamResource resolves to "<prefix>:<value of path param>".
func ParamResource(prefix, param string) ResourceFunc {
	return func(c *gin.Context) (string, error) {
		v := strings.TrimSpace(c.Param(param))
		if v == "" {
			return "", fmt.Errorf("operatorauth: path param %q empty", param)
		}
		return prefix + ":" + v, nil
	}
}

// RequireApprovalFor is RequireApproval with a per-route resource resolver
// (and optional payload override, first spec wins). action is the falcon-id
// action registry name (or a local alias mapped by FalconApprovalConfig.Actions).
func RequireApprovalFor(action string, resource ResourceFunc, payload ...PayloadFunc) gin.HandlerFunc {
	spec := &ApprovalSpec{Resource: resource}
	if len(payload) > 0 {
		spec.Payload = payload[0]
	}
	inner := RequireApproval(action)
	return func(c *gin.Context) {
		c.Set(ctxKeyApprovalSpec, spec)
		inner(c)
	}
}

// FalconApprovalConfig configures the falcon-id backed ApprovalChecker.
type FalconApprovalConfig struct {
	// BaseURL is falcon-id's base URL (e.g. http://falcon-id:8005). Required.
	BaseURL string
	// Audience is this service's audience name in approvals. Required.
	Audience string
	// TokenURL / ClientID / ClientSecret: the service's client_credentials
	// client; it must hold scope platform:ops-approvals-consume. Required
	// unless Tokens is set.
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Tokens overrides the token client (tests).
	Tokens TokenSource
	// Actions maps a local route action to the falcon-id registry action
	// (optional; unmapped actions are sent as-is).
	Actions map[string]string
	// HTTPClient is optional (default 5s timeout).
	HTTPClient *http.Client
}

// TokenSource yields a bearer token for the consume call.
type TokenSource interface{ GetToken() (string, error) }

type falconApprovalChecker struct {
	cfg    FalconApprovalConfig
	tokens TokenSource
	client *http.Client
}

// NewFalconApprovalChecker builds the ApprovalChecker that spends approvals at
// falcon-id POST /internal/v1/ops-approvals/:id/consume. Install it once at
// startup with SetApprovalChecker.
func NewFalconApprovalChecker(cfg FalconApprovalConfig) (ApprovalChecker, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("operatorauth: approval checker needs BaseURL and Audience")
	}
	tokens := cfg.Tokens
	if tokens == nil {
		tc, err := serviceauth.NewTokenClient(serviceauth.TokenClientConfig{
			TokenURL: cfg.TokenURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
			Scope: ApprovalConsumeScope,
		})
		if err != nil {
			return nil, fmt.Errorf("operatorauth: approval token client: %w", err)
		}
		tokens = tc
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &falconApprovalChecker{cfg: cfg, tokens: tokens, client: hc}, nil
}

// Consume implements ApprovalChecker. Fails closed on any error.
func (f *falconApprovalChecker) Consume(c *gin.Context, action string) error {
	actor := ActorFrom(c)
	if actor == nil {
		return errors.New("operatorauth: approval without verified operator")
	}
	id, err := uuid.Parse(strings.TrimSpace(c.GetHeader(HeaderApprovalID)))
	if err != nil {
		return errors.New("operatorauth: approval id missing or malformed")
	}
	v, _ := c.Get(ctxKeyApprovalSpec)
	spec, _ := v.(*ApprovalSpec)
	if spec == nil || spec.Resource == nil {
		return errors.New("operatorauth: route has no approval resource resolver")
	}
	resource, err := spec.Resource(c)
	if err != nil || strings.TrimSpace(resource) == "" {
		return errors.New("operatorauth: approval resource unresolved")
	}
	registry := action
	if m, ok := f.cfg.Actions[action]; ok && m != "" {
		registry = m
	}
	sha := ApprovalPayloadHash(registry, resource)
	if spec.Payload != nil {
		if sha, err = spec.Payload(c, registry, resource); err != nil || sha == "" {
			return errors.New("operatorauth: approval payload unresolved")
		}
	}
	tok, err := f.tokens.GetToken()
	if err != nil {
		return fmt.Errorf("operatorauth: approval token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"audience": f.cfg.Audience, "action": registry, "resource": resource, "payload_sha256": sha,
	})
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.cfg.BaseURL+"/internal/v1/ops-approvals/"+url.PathEscape(id.String())+"/consume", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	if rid := c.GetHeader("X-Request-ID"); rid != "" {
		req.Header.Set("X-Request-ID", rid)
	}
	resp, err := f.client.Do(req) //nolint:gosec // URL from configuration
	if err != nil {
		return fmt.Errorf("operatorauth: approval consume: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("operatorauth: approval consume status %d", resp.StatusCode)
	}
	var out struct {
		ID          string `json:"id"`
		ApproverID  string `json:"approver_id"`
		RequesterID string `json:"requester_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return fmt.Errorf("operatorauth: approval consume decode: %w", err)
	}
	if out.ID != id.String() || out.ApproverID == "" || out.RequesterID == "" {
		return errors.New("operatorauth: approval consume response incomplete")
	}
	// Four-eyes: approved by someone else, and the executing operator is the
	// one who asked for it (an approval id cannot be borrowed).
	if out.ApproverID == out.RequesterID || out.RequesterID != actor.UserID.String() {
		return errors.New("operatorauth: approval not requested by this operator or self-approved")
	}
	return nil
}

// InstallFalconApprovalChecker builds the falcon-id approval checker from the
// service's existing IAM settings (IAM_SERVICE_URL, SERVICE_CLIENT_ID/SECRET)
// and installs it with SetApprovalChecker. audience is this service's name as
// the console puts it in the approval (e.g. "billing"). On error nothing is
// installed, so RequireApproval keeps failing closed.
func InstallFalconApprovalChecker(iamURL, clientID, clientSecret, audience string) error {
	iamURL = strings.TrimRight(strings.TrimSpace(iamURL), "/")
	ac, err := NewFalconApprovalChecker(FalconApprovalConfig{
		BaseURL: iamURL, Audience: audience,
		TokenURL: iamURL + "/oauth/token", ClientID: clientID, ClientSecret: clientSecret,
	})
	if err != nil {
		return err
	}
	SetApprovalChecker(ac)
	return nil
}
