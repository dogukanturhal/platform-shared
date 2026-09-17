# platform-shared

Shared Go libraries consumed by every ExampleSuite platform service repo
(`platform-core`, `platform-commerce`, `platform-engagement`,
`platform-content`, `platform-infra`, `platform-integration`).

This directory lives inside `hexxlock/platform` during the 7-week
extraction sequence and migrates to `hexxlock/platform-shared` in
Week 1. Consumers import it as a versioned Go module — `replace`
directives pointing at sibling checkouts exist only for local
development convenience.

## Module layout

This repo holds **three** Go modules, each released under the same
SemVer tag at every cut:

| Module | Import path | Purpose |
|---|---|---|
| root | `github.com/dogukanturhal/platform-shared` | Core libraries: auth, audit, database, vault, observability, logger, middleware, … |
| `manifest/` | `github.com/dogukanturhal/platform-shared/manifest` | Service manifest schema + loader |
| `storage-sdk/` | `github.com/dogukanturhal/platform-shared/storage-sdk` | Storage abstraction (S3/MinIO) |

The root module re-exports nothing from the submodules; they are
independently importable and each manages its own `go.mod`.

## SemVer policy

- **v0.x.y** — any change is potentially breaking (current phase).
- **v1.0.0 onward** — strict SemVer:
  - **MAJOR** — breaking API change. Module path must add `/v{major}` suffix per Go module rules.
  - **MINOR** — additive (new symbols, new packages).
  - **PATCH** — bug fix, no API change.
- All three modules cut at the same tag, every release. No drift.
- Renovate in consumer repos groups all three under one bump.

## Local development

In a consumer repo (e.g. `platform-core`), the default workflow uses
the published module via the GitLab Go proxy:

```sh
go get github.com/dogukanturhal/platform-shared@v0.1.0
```

For atomic refactor across consumer + shared, opt into the workspace
escape hatch:

```sh
git clone github.com:hexxlock/platform-shared.git ../platform-shared
go work use ../platform-shared        # local-only override
# … edit + test atomically …
go work edit -dropuse ../platform-shared   # before commit
```

`go.work` is gitignored at the consumer side — the workspace is a
development convenience, not a build artifact.

## Genproto replace

This repo's root `go.mod` pins:

```go
replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20260414002931-afd174a4e478
```

The replace prevents legacy pseudo-versions required by older deps
(`go-grpc-middleware v1.4.0`, `envoyproxy/go-control-plane v0.9.x`)
from re-introducing the `googleapis/rpc/status` + `googleapis/api/httpbody`
packages that now live in the split modules. Consumers do NOT need to
mirror this — Go modules resolve the replace transitively from the
require graph.

## CI

- `lint` — golangci-lint across all three modules
- `test` — `go test -race -cover` across all three modules
- `secret-scan` — gitleaks on working tree
- `gosec` — SAST, severity medium+ blocks; SARIF artifact uploaded
- `govulncheck` — Go vulnerability DB scan (currently allow_failure)
- `release` — fires on `v*.*.*` tags, validates major-version rules, warms GitLab Go proxy

## Make targets

```sh
make test         # all three modules
make lint         # all three modules
make vuln         # govulncheck all three modules
make cover        # generate coverage.html
make tag-check TAG=v0.2.0   # verify tag against module path
```

## Releasing

```sh
git tag -a v0.1.1 -m "Brief one-liner"
git push origin v0.1.1
```

The `release` CI job announces the new version to the GitLab Go
module proxy. Renovate then opens grouped bump MRs in each consumer
repo.
