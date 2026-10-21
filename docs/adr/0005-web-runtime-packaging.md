# ADR 0005: Package only the web runtime

Status: Accepted by ARCHITECT for the M0 image-scan remediation.
Owner: PLATFORM. Reviewer: root ARCHITECT.

## Context

The initial web image retained the build toolchain, package managers and development
dependencies. The M0 container scan found HIGH/CRITICAL vulnerabilities in that
expanded runtime surface. A passing native production dependency audit did not
cover all software shipped by the image.

## Decision

Use Next.js standalone output and a separate nonroot Node.js 24 Debian 13
distroless runtime stage. Copy only the traced standalone server/dependencies,
static assets and public assets into the runtime. Start `server.js` directly;
pnpm, npm and the TypeScript build toolchain remain in the build stage. Set the
listen address and port explicitly for Compose, and give runtime files to the
nonroot user. Preserve an empty public directory when the app has no public assets.

Update the build-stage pnpm pin to 10.34.5 to include the fixes identified by the
scan, even though the package manager is excluded from the final runtime. Keep
the frozen lockfile install and the existing application dependencies.

## Consequences and validation

This changes packaging only and does not change API contracts or M0 scope. A
container rebuild, Compose startup, HTTP smoke checks and a HIGH/CRITICAL image
scan must pass before acceptance. Do not suppress findings to meet that gate.
Record their actual results in STATUS.md. The runtime deliberately has no shell;
use container logs and external HTTP checks for diagnosis. The choice is
reversible through the Dockerfile and Next.js configuration.

References: [Next.js standalone output](https://nextjs.org/docs/app/api-reference/config/next-config-js/output),
[Distroless runtime images](https://github.com/GoogleContainerTools/distroless).
