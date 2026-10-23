# ADR 0018: Authenticated stack configuration and CRUD contracts

Status: Accepted by ARCHITECT role, 2026-10-23, for the exact additive contracts
and design below. Owner: CORE-BACKEND; consumers: FRONTEND/ORCHESTRATION.
Scope: WP-1.2 within M1; depends on ADR0011/0016 authorization and QA gates.
This ADR approves later proto edits, not an exposed handler or a completed WP.

## Published compatibility and exact declarations

Keep package `forge.v1`, Go option
`github.com/cavula/forge/gen/go/forge/v1;forgev1`, all existing proto filenames,
`Stack` fields 1–9, Engine values and Run contracts unchanged. Do not move an
existing declaration or reinterpret an existing field. The following additions
are explicitly approved; every other public change needs a new approved ADR.

New `forge/v1/stack_environment.proto` contains:

```proto
message StackEnvironmentVariable {
  string name = 1;
  string value = 2;
}
```

Import that file from existing `entities.proto` and append only these fields to
the existing Stack message:

```proto
repeated StackEnvironmentVariable environment_variables = 10;
uint64 configuration_revision = 11;
```

These values are non-secret configuration visible to organization readers, not
a secret interface. Never add secret plaintext/ciphertext or provider credentials
to Stack. A response's org/ID/created_at/revision are server-assigned metadata.

New `forge/v1/stack_configuration.proto` imports entities/environment and contains
the mutable input type, deliberately excluding org, ID, timestamps and revision:

```proto
message StackConfiguration {
  string name = 1;
  string repository_url = 2;
  string branch = 3;
  string working_directory = 4;
  Engine engine = 5;
  string engine_version = 6;
  repeated StackEnvironmentVariable environment_variables = 7;
}
```

New message files contain exactly these request/response declarations, importing
StackConfiguration and/or Stack where used:

```proto
// stack_create.proto
message CreateStackRequest { StackConfiguration configuration = 1; }
message CreateStackResponse { Stack stack = 1; }

// stack_get.proto
message GetStackRequest { string id = 1; }
message GetStackResponse { Stack stack = 1; }

// stack_list.proto
message ListStacksRequest {
  int32 page_size = 1;
  string page_token = 2;
}
message ListStacksResponse {
  repeated Stack stacks = 1;
  string next_page_token = 2;
}

// stack_update.proto
message UpdateStackRequest {
  string id = 1;
  StackConfiguration configuration = 2;
  uint64 expected_revision = 3;
}
message UpdateStackResponse { Stack stack = 1; }

// stack_delete.proto
message DeleteStackRequest {
  string id = 1;
  uint64 expected_revision = 2;
}
message DeleteStackResponse {}
```

New `forge/v1/stack_service.proto` imports those five message files and defines
only these unary Connect RPCs, introduced incrementally as described below:

```proto
service StackService {
  rpc CreateStack(CreateStackRequest) returns (CreateStackResponse);
  rpc GetStack(GetStackRequest) returns (GetStackResponse);
  rpc ListStacks(ListStacksRequest) returns (ListStacksResponse);
  rpc UpdateStack(UpdateStackRequest) returns (UpdateStackResponse);
  rpc DeleteStack(DeleteStackRequest) returns (DeleteStackResponse);
}
```

There are no request org/role fields, arbitrary filters, field masks, secret flags,
forced deletion, execution or approval methods. Create requires configuration;
ENGINE_UNSPECIFIED defaults to OpenTofu only on Create. Update is complete
replacement, requires every mandatory field and an explicit engine, and an empty
environment list clears that non-secret list. There is no partial-patch inference.
An accepted Update increments revision even when values equal the prior values.

## Validation and non-secret boundary

Reject invalid input with generic field-category errors, without echoing values.
Enforce a 64 KiB uncompressed request limit before decoding; bound all strings in
UTF-8 bytes, reject invalid UTF-8/NUL/control characters and surrounding whitespace.

| Field | Concrete validation |
| --- | --- |
| name | 1–100 bytes; exact case-sensitive name uniqueness within the org, including archived stacks. |
| repository_url | At most 2048 ASCII bytes; absolute HTTPS URL, nonempty DNS/IP host, optional numeric port 1–65535, and nonempty repository path. No userinfo, query (including empty marker), fragment, backslash, percent-encoded path, empty/dot/dot-dot path segments or trailing slash. Path segments use ASCII letters/digits/`._~-`; host is lowercase canonical DNS/punycode or canonical IP spelling. |
| branch | 1–255 UTF-8 bytes; unqualified branch name using Git ref-format restrictions, rejecting leading `-`, `refs/`, `HEAD`, lone `@`, `@{`, `..`, empty/slash-boundary components, components starting `.`, components ending `.lock`, trailing `.`, whitespace/control/DEL and `~^:?*[\\`. No Git command or checkout expansion is invoked. |
| working_directory | `.` for root, otherwise 1–512 UTF-8 bytes of canonical POSIX relative path with nonempty components. No leading slash/tilde, dot/dot-dot components, backslash, colon, percent escape or controls. Never URL-decode or expand it. |
| engine | Only declared OpenTofu/Terraform/Ansible values; reject unknown enum numbers. Terraform remains operator-supplied binary only. Ansible configuration is retained, but M1 execution rejects it; lifecycle/inventory execution remains WP-2.4. |
| engine_version | Required explicit canonical semantic version, at most 64 ASCII bytes, with optional valid prerelease/build identifiers. No `v` prefix, aliases, version ranges, URLs, paths or command arguments. Availability/engine compatibility is an execution prerequisite, not guessed during CRUD. |
| environment_variables | At most 64 entries; unique case-sensitive names matching `[A-Za-z_][A-Za-z0-9_]{0,63}`; each value at most 4096 bytes, total names+values at most 16 KiB. Valid UTF-8, no controls/NUL. Return entries sorted by name. |
| id / expected_revision | IDs are canonical lowercase nonzero UUIDs. Create generates a fresh server UUID. Update/Delete require revision 1 through 9223372036854775807; do not coerce uint64 through JavaScript Number. |

CRUD performs no repository fetch, DNS lookup, filesystem access, shell command,
credential discovery or binary installation. Repository acceptance grants no
network permission: self-hosted/private hosts still need later VCS authentication,
runner egress/SSRF checks and checkout containment before use. After checkout the
runner must independently reject symlink/path escapes; a string check cannot
prove filesystem containment.

Environment input cannot override runner/process/tool configuration. Reserve
`FORGE_`, `LD_`, `DYLD_`, `GIT_`, `SSH_`, `TF_CLI_`, `TF_LOG`, `TF_PLUGIN_`,
`TF_REATTACH_` prefixes and PATH/HOME/USER/LOGNAME/SHELL/IFS/ENV/BASH_ENV/TMPDIR/
TMP/TEMP/PWD/OLDPWD/CDPATH/TF_DATA_DIR/TF_WORKSPACE/TF_IN_AUTOMATION/TF_INPUT.
Also reserve HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY/SSL_CERT_FILE/SSL_CERT_DIR/
SSLKEYLOGFILE and tool-loader PYTHONPATH/PYTHONHOME/NODE_OPTIONS/RUBYOPT/PERL5LIB.
Reserve cloud prefixes AWS_/GOOGLE_/GCLOUD_/CLOUDSDK_/AZURE_/ARM_, except
AWS_REGION, AWS_DEFAULT_REGION, GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_REGION,
GOOGLE_CLOUD_ZONE, ARM_SUBSCRIPTION_ID, ARM_TENANT_ID and ARM_ENVIRONMENT.
Use case-insensitive matching for this reserved-name policy. Also reject names
equal to or ending with `_TOKEN`, `_SECRET`, `_PASSWORD`, `_PRIVATE_KEY`,
`_CREDENTIALS` or `_ACCESS_KEY` (including the corresponding unprefixed names).
TF_VAR_ and ordinary custom non-secret names remain supported outside those rules.

Names cannot prove arbitrary text is non-secret. The UI must label these values
as visible to organization readers; secret variables use WP-1.8's separate
write-only interface. Never log configuration/env values, put them in audit event
payloads, or send them to AI. Do not claim heuristic validation prevents every
mistaken secret entry. Runtime credential/configuration injection has its own
reviewed boundary and may not be overridden by this collection.
Each engine adapter must extend its protected-name policy before execution;
runner-controlled entries always win during environment construction. This list
is not a claim to enumerate every future engine's control variables.

## Authorization, storage and revision binding

Get/List require `metadata.read`; Create/Update/Delete require `resource.write`.
Reader permits only reads; writer/admin permit these CRUD operations. This grants
no state, secret, credential, run-approval or execution permission. Cookie auth
retains exact Origin/CSRF enforcement; token auth needs its separately approved
scope intersection. Bind no handler before authentication/security gates pass.

Resolve membership from verified identity, derive org only from that result, then
use non-owner WithOrg transactions and explicit org predicates on every query.
Re-read matching issuer/subject/user and current role with `FOR SHARE`, held
through the operation, before checking permissions. Lock membership before stack
rows in a consistent order. Current deletion/demotion must serialize with access;
header/resource IDs never establish authority.

Add DB columns for repository, branch, working directory, version, non-secret
environment data, created_at, configuration_revision (positive bigint, initially
1) and nullable deleted_at. Preserve composite keys/FKs/forced tenant RLS and
existing engine mapping. Store only typed validated configuration; canonicalize
environment ordering and parameterize SQL. Existing rows need a documented,
reversible migration/backfill; never fabricate a repository/version for them or
silently expose incomplete records as runnable stacks.

Create inserts the stack and `stack.created` audit event atomically. Update/Delete
lock its active row `FOR UPDATE`, compare expected_revision, then increment it
without overflow and append `stack.updated`/`stack.deleted` audit in that same
transaction. Audit uses authorized actor/org/stack IDs and fixed action, without
configuration values. Failed authorization, conflict or audit insertion changes
neither stack nor audit. Never drop or weaken the append-only audit trigger.

Before Update/Delete, reject any nonterminal/unknown run status and any active
state lock; callers cancel/discard/unlock through their separately authorized
interfaces first. Run creation and state-lock acquisition must lock that stack
`FOR SHARE`, check it is active, and hold through their transaction; this closes
the enqueue/lock-versus-archive race. Their own ADRs/wiring must integrate this
guard before those paths become reachable; absence of a runtime path is not a
successful isolation test.

Each future run snapshots exact configuration revision and immutable configuration
plus resolved commit. Bind its saved binary plan/policy/approval to that org,
stack, revision and artifact digest; apply must revalidate the active current
revision. Updating configuration cannot authorize or silently reuse an older
approval/plan. Those Run/API/workflow contracts need their own approved ADRs;
this ADR changes neither existing Run wire fields nor permits apply.

Delete is archival: set deleted_at and retain the row, revision, name reservation,
run/state/secret references and all audit history. Never cascade-delete, purge
state or remove locks. Revoke runtime hard DELETE on stacks. Ordinary Get/List/
Update/Delete exclude archived rows; repeated Delete returns NotFound. Historical
state/run access remains governed by its own permissions, without permitting new
work against the archived stack. Restore/hard purge requires a separate design.

## Pagination and errors

List has default page_size 20; accept 1–20, reject negative or larger values.
Order active rows by UUID ascending with keyset pagination, explicit org filter,
and limit+1. The token is canonical unpadded base64url of ASCII
`v1:<authorized-org-UUID>:<last-returned-stack-UUID>`, at most 128 bytes; reject
other versions, malformed UUIDs or org mismatch. It is a position marker, not a
credential/signature/snapshot: never adopt its org as authorization. Modifying a
valid cursor can only move within the caller's authorized set. Concurrent changes
may alter later pages; no snapshot consistency or arbitrary sorting is promised.
next_page_token is empty at the end. Bound encoded responses to 4 MiB and test
worst-case protobuf and JSON escaping with the environment limits above.

Missing credentials return Unauthenticated; failed membership/role/scope returns
PermissionDenied. Within an authorized org, absent/foreign/archived IDs return
the same NotFound. Invalid input/token returns InvalidArgument; same-org duplicate
name AlreadyExists; stale revision Aborted; active work/lock or revision exhaustion
FailedPrecondition; storage failures Internal with generic diagnostics. No error
echoes another org, resource values, URLs, variables or SQL/provider details.

## Review slices and acceptance

Introduce environment type first, then additive Stack fields, then configuration
type; generate Go/Connect/TypeScript and wire-test each independently. If either
generated diff exceeds the limit, append one approved field per slice. Introduce
each RPC request/response file separately, splitting request and response into
separate commits/PRs in that same stable filename when necessary. Introduce
StackService with GetStack only after its messages, then append one approved RPC
per subsequent slice; do not land one oversized five-method service patch.

Each published PR is strictly below 500 changed lines including generated files,
tests/docs. Measure against its actual retargeted base before review. Every proto
slice regenerates all clients and passes buf lint/build/breaking against the real
base plus Go/TS wire/descriptor checks; do not update the M0 baseline to hide a
break. Backend helpers and frontend mocks may use the approved generated contract
in parallel; no insecure stub or public handler substitutes for completed auth.

Implement migrations/validation, tenant storage reads, each mutation/audit path,
then handlers as separate tested slices. QA-SECURITY reviews authentication,
tenant/state/run locking and secret boundaries before exposure. Real PostgreSQL
tests use non-owner/NOBYPASSRLS roles and prove both tenant directions, missing
context, role denials, membership demotion/deletion serialization, stale revisions
and exactly one mutation/audit winner under concurrent updates/delete. Prove audit
failure rollback, archived-row exclusion, unchanged history/FKs, duplicate-name
handling, pagination boundaries and pooled-context reset. Later run/state wiring
must prove the active-work/lock races and stale-plan rejection before its gate.

Use adversarial URL/ref/path/version/env and unknown-enum tests, payload/diagnostic
leak checks, >=70% business coverage, I/O integration and full hosted CI including
vulnerability/image checks. WP-1.2 is DONE only after its complete authenticated
CRUD acceptance passes CI; M1 still stops at the full LocalStack MVP gate before
M2. An accepted contract alone neither completes a WP nor authorizes deployment.

References: [protobuf evolution](https://protobuf.dev/programming-guides/proto3/#updating),
[Git ref validation](https://git-scm.com/docs/git-check-ref-format),
[PostgreSQL row locks](https://www.postgresql.org/docs/16/explicit-locking.html#LOCKING-ROWS).
