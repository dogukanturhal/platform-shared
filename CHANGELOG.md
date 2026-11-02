# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before
v1.0.0, any minor release may contain breaking changes.

## [Unreleased]

### Added

- `operatorauth`: verification of short-lived operator assertions, step-up and
  four-eyes approval middleware, and audit event emission for operator routes.
- `tenantpurge`: the participant side of a Kafka-driven tenant purge (plan,
  quiesce and erase phases, retention rules, acknowledgements).
- `permissions`: registration from an in-memory manifest
  (`RegisterFromManifestBytes`, `ParseManifest`) so manifests can be embedded
  with `go:embed`.
- `auth`: pluggable `PermissionChecker`, opt-in logging of issuer checks, and
  RS256 validation through a JWKS endpoint.
- `service-auth`: JWKS-based middleware and validator, scope audit.
- `quota`: reserve, confirm and release holds.
- `vault`: Kubernetes auth, KV v1 writes and transit-based token protection.
- `tools/analyzers/nilerrwrap`: a `go/analysis` pass for `fmt.Errorf("%w", err)`
  on a path where `err` can be nil.
- Public repository scaffolding: README, CI (vet, race tests, golangci-lint,
  govulncheck, CodeQL, OpenSSF Scorecard), Dependabot, tag-based releases,
  CONTRIBUTING (DCO), SECURITY, CODE_OF_CONDUCT and issue templates.

### Changed

- Internal host names, product names and tracker references were removed or
  replaced with neutral placeholders in code, tests and comments. The browser
  cookie read by `auth` is now `access_token`, and the standard Vault mappings
  use a placeholder payment provider name.
- Nested modules (`manifest`, `storage-sdk`, `tools/analyzers/nilerrwrap`) carry
  their own `LICENSE` file.

### Removed

- The quota registry CLI and manifest tooling (`cmd/quota-registry`,
  `quota/manifest`), which were specific to a private deployment.
- Internal design notes and a release helper script.

## [0.5.1]

### Fixed

- TenantConnectionManager now honours the tenant's host and port when building
  connection strings (#20).

## [0.3.1]

The version recorded in `VERSION.txt` at the time of this sync. No tag has been
cut from the public repository yet.
