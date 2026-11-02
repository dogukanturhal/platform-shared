# platform-shared

[![CI](https://github.com/dogukanturhal/platform-shared/actions/workflows/ci.yml/badge.svg)](https://github.com/dogukanturhal/platform-shared/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dogukanturhal/platform-shared.svg)](https://pkg.go.dev/github.com/dogukanturhal/platform-shared)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecard.dev/projects/github.com/dogukanturhal/platform-shared/badge)](https://securityscorecard.dev/viewer/?uri=github.com/dogukanturhal/platform-shared)

Go packages for building multi-tenant HTTP services: authentication, tenant
isolation in PostgreSQL, quota checks, an outbox, outbound resilience and Vault
access.

## Who it's for

Teams running several Go services (Gin, PostgreSQL, Redis, Kafka, Vault) that
share one identity provider and want the same auth, tenancy and resilience code
in each of them instead of a private copy per service. It is extracted from a
set of internal services and is used by [falcon-id](https://github.com/dogukanturhal/falcon-id).
The identity-provider-specific packages (`permissions`, `manifest`,
`operatorauth`, `service-auth`) assume that server's API.

If you want a framework, this is not one. It is a set of libraries you import
one at a time.

## What is in it

This repository holds four Go modules. Only the first two are meant to be
imported by most users.

| Module | Import path |
|---|---|
| root | `github.com/dogukanturhal/platform-shared` |
| `manifest/` | `github.com/dogukanturhal/platform-shared/manifest` |
| `storage-sdk/` | `github.com/dogukanturhal/platform-shared/storage-sdk` |
| `tools/analyzers/nilerrwrap/` | `github.com/dogukanturhal/platform-shared/tools/analyzers/nilerrwrap` |

Packages in the root module. The stability column says how much I would trust
the API not to move, given that everything is v0.x and may still break:
**stable** = used in production by sibling services and covered by tests;
**evolving** = used, API still changing; **thin** = small or little tested.

| Package | What it does | Stability |
|---|---|---|
| `auth` | JWT validation (HS256, and RS256 through a JWKS URL), API keys, Gin middleware (`RequireAuth`, `RequirePermission`, `RequireRole`), pluggable permission checker | stable |
| `auth/falconauthz` | `PermissionChecker` that asks falcon-id for a user's permissions | evolving |
| `service-auth` | Service-to-service JWTs: signing client, JWKS validator and middleware, scope audit | stable |
| `operatorauth` | Verifies short-lived operator assertions, step-up (fresh MFA) and four-eyes approval middleware, audit events for operator routes | evolving |
| `tenant` | Tenant and realm in `context.Context`; `SET LOCAL` helpers for PostgreSQL row-level security (`database/sql`, pgx, sqlx); Gin middleware | stable |
| `database` | Connection pools, per-product and per-tenant connection routing, credential rotation, RLS bootstrap | evolving |
| `quota` | Client for a quota service: check, usage, reserve/confirm/release holds, cached registry | stable |
| `tenantpurge` | Participant side of a Kafka-driven tenant purge saga: plan, quiesce, erase, retention rules, acks | evolving |
| `outbox` | Transactional outbox on pgx: migration SQL, repository, retrying worker pool with a reaper | evolving |
| `resilience` | Circuit breakers (counter and sliding window), retrying HTTP client, bulkhead, Redis distributed lock | stable |
| `circuitbreaker` | gobreaker v2 wrapper with a named registry, per-host `http.RoundTripper` and Prometheus metrics | evolving |
| `httpclient` | Factory for HTTP clients with timeouts, retries and a breaker | thin |
| `vault` | HashiCorp Vault client: KV, transit, Kubernetes auth, database credentials, token protection | evolving |
| `mtls` | mTLS server and client configuration, certificate loading, identity middleware, Vault PKI | thin |
| `middleware` | Gin middleware: Redis rate limiter, idempotency keys, ETag, request id, size limit, recovery, security headers | stable |
| `audit` | Audit entries and middleware for mutations; immutable log helpers | evolving |
| `permissions` | Registers a service's permission manifest with falcon-id (from a file or embedded bytes) | evolving |
| `manifest` (package) | Resource self-registration client for falcon-id | thin |
| `metrics`, `tracing`, `observability`, `logger` | Prometheus and SLO metrics, OpenTelemetry setup, trace ids in zap logs, zap factory | evolving |
| `errors`, `response` | API error codes and Gin response helpers | stable |
| `security`, `sanitizer` | URL and redirect validation (SSRF guards), HTML sanitising | evolving |
| `hooks` | Webhook engine for auth events (sync allow/deny and async) | thin |
| `config`, `defaults`, `domain`, `version` | Env helpers, shared defaults, domain verification constants, `/version` handler | thin |

`tools/analyzers/nilerrwrap` is a `go/analysis` pass that finds
`return ..., fmt.Errorf("...%w...", err)` on a path where `err` can be nil.

## Quickstart

Add the module to a service:

```sh
go get github.com/dogukanturhal/platform-shared@main
```

No version has been tagged from this repository yet, so `@main` is what
works today.

### 1. Authenticated, tenant-scoped handler

```go
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/platform-shared/auth"
	"github.com/dogukanturhal/platform-shared/tenant"
)

func main() {
	pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}

	mw := auth.NewMiddleware(&auth.Config{
		JWTSecret: os.Getenv("JWT_SECRET"),
		JWTIssuer: "my-idp",
	})

	r := gin.New()
	api := r.Group("/api", mw.RequireAuth())
	api.GET("/contacts/:id", mw.RequirePermission("crm:contacts:read"), func(c *gin.Context) {
		tenantID, ok := auth.GetTenantID(c)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		// Runs in a transaction with `SET LOCAL app.current_tenant_id`, so
		// row-level security policies see the caller's tenant.
		var name string
		err := tenant.WithTenantPgx(c.Request.Context(), pool, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(c.Request.Context(),
				"SELECT name FROM contacts WHERE id = $1", c.Param("id")).Scan(&name)
		})
		if err != nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.JSON(http.StatusOK, gin.H{"name": name})
	})
	_ = r.Run(":8080")
}
```

The RLS policy itself is yours to write; `database/rls_template.sql` is a
starting point.

### 2. Outbound calls with retries and a circuit breaker

```go
cb := resilience.NewCircuitBreakerWithConfig(5, 30*time.Second) // open after 5 failures, retry after 30s
client := resilience.NewResilientHTTPClient(
	resilience.WithMaxRetries(3),
	resilience.WithRetryDelay(100*time.Millisecond),
	resilience.WithCircuitBreaker(cb),
)

req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://billing.internal/v1/plans", nil)
resp, err := client.Do(req)
if errors.Is(err, resilience.ErrCircuitOpen) {
	// fail fast, serve a fallback
}
```

### 3. Write an event in the same transaction as your data

```go
// once, in a migration:
//   pool.Exec(ctx, outbox.MigrationSQL("orders_outbox"))
repo := outbox.NewRepository(pool, "orders_outbox")

registry := outbox.HandlerRegistry{
	"email.send": outbox.HandlerFunc(func(ctx context.Context, ev *outbox.Event) error {
		// ev.Payload is the JSON you enqueued. Handlers must be idempotent:
		// delivery is at least once.
		return sendEmail(ctx, ev.Payload)
	}),
}
worker := outbox.NewWorker(repo, registry, logger, outbox.WorkerOptions{})
worker.Start(ctx)
defer worker.Stop()

// in a request handler:
tx, _ := pool.Begin(ctx)
defer tx.Rollback(ctx)
// ... insert the order using tx ...
if _, err := repo.Enqueue(ctx, tx, orderID, "email.send", map[string]string{"to": addr}); err != nil {
	return err
}
return tx.Commit(ctx)
```

### Running the tests

```sh
git clone https://github.com/dogukanturhal/platform-shared
cd platform-shared
make test      # go test -race in the root module, manifest and storage-sdk
make lint      # golangci-lint, same modules
make vuln      # govulncheck, same modules
```

Tests that need a live PostgreSQL carry the `integration` build tag and are
not run by `make test`. Redis-backed code is tested against miniredis.

## How it compares

- **Writing it yourself per service.** That is the alternative this replaces.
  The cost is that fixes land in one place, and the price is that you take the
  library's opinions: Gin, pgx or sqlx, zap, Prometheus.
- **go-kit, Kratos, go-micro.** These are frameworks with their own transport
  and service model. This is smaller and narrower: it does not own your `main`,
  and it targets multi-tenant PostgreSQL services specifically (RLS, per-tenant
  routing, purge).
- **Single-purpose libraries** such as `sony/gobreaker`, `golang-jwt/jwt` or
  `cenkalti/backoff`. If you only need one thing, use those directly; several
  packages here are thin layers over them. The value here is that the pieces
  already agree on one tenant and claims model.
- **A service mesh** handles mTLS and retries outside the process. The
  `resilience` and `mtls` packages are for when you have no mesh or want the
  behaviour in-process.

## Architecture

```
            +-------------------+        +-------------------+
 request -> | auth / service-   | -----> | tenant            |
            | auth / operatorauth|  tid  | ctx + SET LOCAL   |
            +-------------------+        +---------+---------+
                     |                             |
                     v                             v
            +-------------------+        +-------------------+
            | middleware        |        | database (pools,  |
            | rate limit, etag, |        | routing, rotation)|
            | idempotency       |        +---------+---------+
            +-------------------+                  |
                                                   v
   +------------+   +----------+   +----------------------------+
   | quota      |   | outbox   |-->| Kafka / HTTP side effects  |
   | tenantpurge|   | worker   |   | via resilience + breakers  |
   +------------+   +----------+   +----------------------------+

   vault, mtls, metrics, tracing, logger: used by all of the above
```

Identity and permissions come from an external server (falcon-id in our case);
these packages verify its tokens and call its HTTP API, they do not issue
tokens themselves.

## Status and limitations

- Everything is **v0.x**. Minor releases may break the API. From v1.0.0 the
  root module follows strict SemVer.
- No version has been tagged from this repository yet. The nested modules need
  their own tags (`manifest/vX.Y.Z`, `storage-sdk/vX.Y.Z`) when they are cut.
- Several packages encode assumptions of the system they came from: the
  permission string format (`module:resource:action`), the claim names in
  tokens, the Vault path layout in `vault.StandardMappings`, and falcon-id's
  HTTP API. Expect to adapt them if your identity provider differs.
- `permissions`, `manifest` (package), `auth/falconauthz` and `operatorauth`
  only make sense next to falcon-id.
- Test coverage is uneven. `resilience`, `middleware`, `service-auth`, `auth`
  and `tenant` are well covered. `config`, `outbox`, `tracing`, `logger`,
  `domain`, `defaults` and `version` have no unit tests of their own, and
  `operatorauth`, `mtls` and `quota` have a single test file each.
- The build pins Go 1.25. The nested `manifest` and `storage-sdk` modules
  declare 1.24.
- Not a security product: the SSRF and redirect validators in `security` help
  but are not a substitute for network egress controls.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off. Everyone
taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md). Do not open public issues for them.

## License

Apache License 2.0. See [LICENSE](LICENSE).
