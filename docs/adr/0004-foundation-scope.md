# ADR 0004: M0 executable scaffolding and milestone boundaries

Status: Accepted by ARCHITECT for the M0 foundation scope.

## Context

The roadmap requires runnable development scaffolding before the M1 core loop.
Implementing orchestration, authentication or AI in M0 would bypass milestone
acceptance and create security claims without their required tests.

## Decision

Create the documented monorepo directories and minimal executable entrypoints,
Next.js application and local PostgreSQL 16/Temporal services. Keep modules without
M0 behavior as documented placeholders. Use the decided Go, Connect/protobuf/buf,
TypeScript/Next.js and OpenTelemetry stack; no substitute transport or database.
Expose only foundation health/readiness behavior where present. Do not pretend
that runner execution, cloud credentials, secret encryption, state backend,
webhook processing, policy authorization or AI workflows are available.

Use real PostgreSQL integration tests for tenant isolation. Keep development
configuration visibly local and reversible. Contract decisions belong to their
own ARCHITECT-approved ADR; this ADR does not authorize subsequent API changes.

## Consequences

A clean clone can exercise development startup, contract generation, migrations,
CI and isolation without real cloud credentials. M0 remains small and reviewable;
M1 starts only after the user receives the M0 package/validation report. Placeholder
modules carry no business-logic coverage claim. Production hardening and later
milestone features remain explicitly deferred.

Validation: CI foundation checks and the M0 status report are the evidence of
completion; the presence of this ADR alone does not establish passing acceptance.
