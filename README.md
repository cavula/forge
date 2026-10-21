# Forge

Self-hostable Apache-2.0 IaC orchestration foundations. **M0 only**: no login,
IaC execution, state HTTP backend or AI operations are available yet.
The unmodified [roadmap](docs/BRIEF.md) is the source of truth.

## Development

Prerequisites: Docker Engine/Desktop with Compose v2.24+ (Linux containers),
Make and curl. Ports 3000, 5432, 7233 and 8080 must be available.

```sh
make dev
```

This builds the Go control plane and Next.js UI, starts PostgreSQL 16 and
Temporal, applies embedded goose migrations as the owner, and smoke-tests the
application. First boot needs internet access to pull images/dependencies.
Generated clients are committed, so development startup needs no host Go, Node
or buf. UI: http://localhost:3000; health/readiness: http://localhost:8080/healthz
and `/readyz`; Temporal gRPC: localhost:7233.

```sh
make down                     # preserve database volume
# Destructive local reset, only when you want to delete development data:
# docker compose -f deploy/compose/compose.yaml down --volumes
```

Compose credentials are public **development-only** values. Services bind to
loopback; no cloud credentials or master encryption key are needed in M0.
The application receives only `forge_app` credentials; the one-shot migration
container and Temporal bootstrap use the owner. Production provisioning must
separate Temporal and Forge database owners and replace development credentials.

## Checks outside Docker

Install Go 1.26.10+, Node 24, pnpm 10.34.5 and Make. The roadmap permits Go 1.23+;
current dependencies require 1.26, which is the reproducible CI/image baseline.

```sh
make tools web-install generate
make lint test build breaking
# After starting PostgreSQL and applying deploy/compose/init.sql:
make migrate
make integration
python3 scripts/check-coverage.py coverage.out
.tools/govulncheck ./...
pnpm --dir web audit --prod --audit-level high
```

`make test` skips PostgreSQL tests unless `TEST_DATABASE_URL` is set. CI sets it
and also runs the explicit `make integration` gate. To measure database coverage
locally, set `TEST_DATABASE_URL` before `make test`. `make integration` uses a
non-owner, non-superuser role. `DATABASE_URL` is only for the migration command;
use runtime credentials when launching `cmd/server` directly. Both Make defaults
are local Compose URLs and can be overridden. Migrate down with
`DATABASE_URL=... go run ./cmd/migrate down`; rollback deletes foundation data.

`make check` runs generation, lint, tests, builds, breaking detection and
`govulncheck`. Full CI additionally runs migrations both ways, PostgreSQL tests,
coverage >=70% for implemented helpers, production web audit, Compose smoke and
server/web image scans. Generated clients must remain identical after generation.
`BUF_BREAKING_AGAINST` can select a Git SHA; bootstrap uses the committed M0
protobuf descriptor. Do not refresh that baseline to hide a breaking change.

## Layout and boundaries

- `proto`, `gen/go`, `web/src/gen`: approved protobuf source and generated clients.
- `cmd/{server,worker,runner,forgectl}`: control plane and future process entrypoints.
- `cmd/migrate`, `internal/database`: goose migrations, forced RLS and tenant helper.
- `internal/{auth,orgs,stacks,runs,state,vcs,policy,secrets,audit,ai,mcp,compliance,registry,blueprints}`: roadmap module boundaries.
- `web`: minimal Next.js/TypeScript foundation page.
- `policies`, `deploy/{compose,helm}`, `e2e`: staged roadmap boundaries.
- `docs`: [status](docs/STATUS.md), [questions](docs/OPEN_QUESTIONS.md),
  [threat model](docs/THREAT_MODEL.md), [ADRs](docs/adr).

The public Connect RPC `/forge.v1.FoundationService/GetInfo` returns build metadata
only. Tenant context is not accepted over HTTP. Authentication and authorized
organization selection must precede M1 database endpoints. RLS supplements that
boundary; a custom PostgreSQL setting is not an authentication system.

HTTP requests have OpenTelemetry instrumentation, a tracer provider and W3C
trace-context propagation. Exporters, metrics dashboards and production
observability belong to later milestones. Logs are structured and omit raw
configuration/database errors; a shared secret-leak assertion protects HTTP output.
State/secret columns reserve envelope ciphertext, nonce, wrapped DEK and key ID;
actual encryption and key provisioning must be implemented before M1 writes.

Architecture choices and pending validation are explicit in the status and ADRs.
No M1 work starts before the M0 acceptance gates pass.

References: [Connect](https://connectrpc.com/docs/introduction/),
[Buf generation](https://buf.build/docs/generate/),
[Next.js installation](https://nextjs.org/docs/app/getting-started/installation),
[Temporal PostgreSQL Compose example](https://github.com/temporalio/docker-compose/blob/main/docker-compose-postgres.yml).

The web runtime uses Next.js standalone output in a nonroot distroless image;
package managers and development dependencies stay in the builder (ADR0005).
On macOS, if Docker Desktop is running but `docker` is not on PATH, use
`PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH" make dev`.
