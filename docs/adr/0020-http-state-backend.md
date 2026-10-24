# ADR 0020: M1 HTTP state storage, locking and apply fencing

Status: Accepted by root ARCHITECT after cross-review, 2026-10-23.
Mandatory independent QA-SECURITY and CI gate every sensitive implementation.
Owner: CORE-BACKEND; architectural owner: ARCHITECT. Scope: WP-1.3 within M1.
Dependencies: ADR0002/0003/0009–0011/0013/0017 tenant/auth/encryption boundaries,
ADR0018 active stacks, ADR0019 immutable run admission, WP-1.6 trusted supervision.
This design authorizes only the exact later implementation below; no endpoint
binding, credential issuance or execution is enabled by this document. Existing StateVersion fields and every existing wire contract stay
unchanged. Stop at the real LocalStack M1 acceptance gate before M2 work.

ARCHITECT approves the concrete routes, job-only capabilities, schema, local-key
provider and recovery semantics below. Existing forced-RLS, explicit org queries,
AES-GCM envelope, append-only audit and no-timeout-unlock invariants remain.
Implementation and exposure still require independent QA-SECURITY and hosted CI.

## Protocol evidence and deliberately bounded compatibility

OpenTofu documents GET reads, POST writes, and optional LOCK/UNLOCK requests with
JSON lock information. Successful locking uses 200; contention uses 409 or 423 and
holding-lock JSON. Locking addresses must be explicitly configured. Credentials
belong in environment configuration because backend arguments can enter saved
plans and .terraform data. [OpenTofu HTTP backend](https://opentofu.org/docs/language/settings/backends/http/)

The v1.11.0 HTTP client uses uppercase `ID` in write queries; GET accepts 204/404
as absence; POST accepts 200/201/204; UNLOCK expects 200 and sends a JSON lock ID.
Its lock-success return value is its own requested ID, so the backend must retain
that client nonce. These observations are compatibility evidence, not authority.
[OpenTofu v1.11.0 client](https://raw.githubusercontent.com/opentofu/opentofu/v1.11.0/internal/backend/remote-state/http/client.go)

Terraform documents the same default verbs and lock-status convention.
[Terraform HTTP backend](https://developer.hashicorp.com/terraform/language/backend/http)

Forge defines this subset; integration CI must pin and record exact OpenTofu
binary versions/digests. Terraform is operator-supplied only; test its selected
version separately before claiming support. One stack is one state; named HTTP
backend workspaces, migration/import bypasses, remote-state data sharing and
client-side encrypted state envelopes are outside this first M1 interface.
Server-side encryption is mandatory. Do not silently accept an unknown format.

| Route and verb | Successful result | Preconditions |
| --- | --- | --- |
| `GET /v1/stacks/{stack}/state` | 200 exact bytes; 204 if initialized with no version | Valid stack-bound state read capability. |
| `POST /v1/stacks/{stack}/state?ID={lock}` | 200 empty body | Admitted apply job, exact current lock/capability/fence and valid snapshot. |
| `LOCK /v1/stacks/{stack}/state/lock` | 200 empty body | Trusted job reservation; canonical JSON `ID`; acquire or replay its lock. |
| `UNLOCK /v1/stacks/{stack}/state/lock` | 200 empty body | Same job/capability/fence and exact JSON `ID`; acknowledge release intent. |

All routes require HTTPS and verified certificates; explicit loopback HTTP is
allowed only in isolated development/tests. No redirects, URL credentials,
cookie authentication, CORS credentials, method overrides, proxy-auth headers or
alternate write methods. DELETE returns 405; retaining versions is intentional.
No GET query selects a version or tenant. POST accepts exactly one raw query item
`ID=<canonical-lowercase-nonzero-UUID>`, without alternate escaping or extra keys;
other routes reject queries. Stack/lock IDs use that same canonical UUID syntax.
Ingress must pass LOCK/UNLOCK unchanged and enforce the same bounds as the server.

For an authorized stack, absent state is 204, never synthesized JSON. Absent,
foreign or unauthorized archived stack lookup is the same 404. Invalid/missing
credentials return generic 401 with Basic challenge; a verified capability denied
for that verb returns 403; a different stack selector is uniformly 404 without
probing its existence. Malformed input is 400; unsupported encoding/media
is 415; oversized bodies are 413; stale serial/lineage is 409; lock mismatch or
contention is 423; unavailable key/storage is generic 503. Unknown stack and empty
state must never be confused inside storage. No raw SQL/SDK/JSON diagnostic leaves
the server. Responses use Cache-Control: no-store and X-Content-Type-Options:
nosniff. Disable intermediary caching and payload/query/header capture.

A 423 response contains generated lock JSON with the holding nonce, server-set
Created timestamp and fixed Operation/Who/Info/Path/Version values; never echo
submitted descriptions, usernames, paths or versions. The conflict body reveals
nothing across tenants and grants no authority to unlock. All other errors have
fixed safe bodies below 1 KiB. Omit Content-MD5 responses; compute SHA-256 on the
server for identity. An optional client Content-MD5 may be checked as transport
corruption detection only and never participates in authorization or deduplication.

## Credential and authorization boundary

The HTTP backend accepts only Basic username `forge`, with the opaque state
capability as password. Exactly one Authorization value is allowed. No general
Forge API token, browser cookie, org header, URL ID or lock body establishes state
authority. `metadata.read`/`resource.write` retain no state access, including for
admin. This ADR grants no new human state permission or public issuance RPC.

Trusted control-plane admission alone can mint job capabilities. Use
`forge_state_v1.<selector>.<secret>`: independently random 16-byte selector and
32-byte secret, canonical unpadded base64url, complete-token SHA-256 verifier and
constant-time comparison. Store only verifier/binding metadata; display/deliver
plaintext once to the isolated job through its protected runtime channel.
The trusted runner fixes the HTTP backend origin, paths, methods and TLS settings;
reject conflicting repository backend/credential settings before delivering a
capability. Extend ADR0018's engine protected-name policy to all TF_HTTP_ names.
Repository/environment values cannot redirect credential-bearing requests. Supply
credentials through the controlled process environment, never backend arguments;
prove the selected saved-plan/init path cannot replace them with older credentials.
A narrow SELECT-only forced-RLS selector lookup obtains verifier metadata before
an org is adopted, following ADR0011. It exposes no tenant resources; a valid
verifier, expiry and revocation check must precede using its stored org binding.
Unknown selectors and wrong passwords share the same generic authentication error.

Bind each record to one org, active stack, run, immutable job ID, phase, positive
fence, allowed verbs, audience `forge.http-state.v1`, issuance/expiry and revocation.
IDs/verbs cannot be broadened by headers or refresh requests. Prepare/plan jobs
receive GET/LOCK/UNLOCK only; POST is exclusive to the BeginApply-admitted job.
Use expiry no later than its trusted job deadline plus five-minute cleanup budget,
with hard maximum 65 minutes. Init/read-only test jobs use at most ten minutes.
There is no refresh that creates a new job, changes a fence or extends the approved
execution deadline. Trusted cleanup may receive a separate UNLOCK-only capability.

On every request, recheck capability scope/expiry/revocation and current stored
job/reservation status inside WithOrg. Unknown statuses deny. Only trusted
admitted/running/reconciling jobs retain phase-specific verbs. Re-read the enqueue
actor's current writer/admin membership and, for apply, the human approver's
current admin membership; missing/demoted membership denies further access. Authenticated admission remains ADR0019's duty;
state capability possession is neither human approval nor cloud permission.
Revocation during apply can prevent final state persistence: retain/quarantine the
gate and arrange trusted encrypted recovery; never pretend cloud changes reverted.

Serialize using one common order: current membership rows in UUID order, stack,
run, state slot, capability and affected version rows. Use FOR SHARE on memberships
and the active stack through each operation; writers serialize the state slot
FOR UPDATE. Every query includes the authorized org and resource predicates under
a non-owner/NOBYPASSRLS role and FORCE RLS. Revalidate selector metadata after
resolution; clear all auth/tenant lookup context on pooled transaction boundaries.
Archived stacks accept no new jobs/locks/writes; retained history requires a later
explicit recovery read capability, never accidental access via this route.

## Durable reservation, native lock nonce and fence

Use one durable coordination row per `(org_id,stack_id)` for current head and the
exclusive job reservation, shared with ADR0019's apply gate. Never keep authority
only in process memory, a cache, Temporal history or an expiring lease. Allocation
increments a positive bigint fence without wraparound; exhaustion fails closed.
Historical reservation identities and retired lock nonces remain tombstoned.

Prepare/GeneratePlan obtain a read-job reservation through trusted admission after
checking the active stack and current run. Only that job can attach a native LOCK
nonce. Once planning is durably complete and its process is confirmed quiescent,
release its reservation. BeginApply later compares the bound base state/version
(or explicit `none`), all ADR0019 inputs and current approval, then atomically
reserves the apply job/fence before any write capability or process is launched.
No plan lock, client Operation field or raw LOCK request can admit apply.

Lock JSON permits only ID, Operation, Info, Who, Version, Created and Path; ID
is mandatory. Other fields are optional bounded UTF-8 strings with no controls:
Operation/Version/Created <=64 bytes, Info <=512, Who <=256, Path <=1024. Reject
duplicates/unknown fields, wrong types and trailing data; none supplies authority.

LOCK atomically checks the authorized reservation, active stack, job/fence and
absence of a different attached lock. Persist the client ID plus server-derived
org/stack/run/job/fence and timestamp. Identical same-owner LOCK retries return 200
without allocating another fence or audit event; a different owner/nonce gets
423 with sanitized holder metadata. A previously retired nonce can never be
reacquired, even by a later job. No public lease/expiry automatically frees it.

POST requires the attached live lock nonce to equal query ID and the capability's
stored job/fence to equal the slot's current admitted apply owner. Missing locks,
`-lock=false`, stale jobs, retired nonces and lost-fence writers fail closed, even
when no other client appears active. The fence is server-side metadata; no
unverified custom fence header is required from the native client. Recheck the
immutable admitted configuration/binding. Cancellation must prevent BeginApply before
launch; once launched, cancellation uses supervised stop/reconciliation while
retaining this job's state-finalization authority until unlock intent/quiescence,
subject to the explicit credential revocation/expiry rules above.

UNLOCK verifies owner/fence/nonce, atomically marks `unlock_requested`, disables
further writes and returns 200; identical authorized retries remain 200. It does
not itself free the reservation. The trusted supervisor must prove process
quiescence and persist final state/outcome before it releases the slot and revokes
capabilities. Timeout, disconnect, expiry, cancellation, runner claims or a native
unlock request alone cannot prove quiescence. Uncertainty marks QUARANTINED,
retains gate/lock and produces APPLY_OUTCOME_UNKNOWN under ADR0019.

An untrusted process cannot make itself a new owner by guessing a lock nonce.
Fences block stale state writes; they do not stop an old process's cloud API calls.
At-most-once launch and confirmed stop remain WP-1.6/ADR0019 responsibilities.
Force-unlock is intentionally denied through this native route; knowledge of the
nonce cannot bypass the job capability or quiescence requirement. OpenTofu itself
warns that unlocking a live writer risks concurrent state modification.
[OpenTofu locking guidance](https://opentofu.org/docs/language/state/locking/)

## Snapshot validation, versions and replay

Treat every state byte as sensitive. GET returns authenticated decrypted bytes
unchanged. POST stores the exact validated bytes, without normalizing resources,
interpreting provider configuration or fetching referenced URLs. State commonly
contains credentials and other sensitive attributes.
[OpenTofu sensitive-state guidance](https://opentofu.org/docs/language/state/sensitive-data/)

Bound state bodies and decrypted responses to 16 MiB, lock bodies to 4 KiB,
request targets to 512 bytes and total headers to 8 KiB. Require application/json
(optional UTF-8 charset), identity Content-Encoding and valid UTF-8 without BOM.
Bound reads before parsing, including chunked bodies; reject trailers, duplicate
Authorization/Content-Length and ambiguous framing at ingress/server. Use 10s
header, 60s body/response and 15s idle timeouts, plus a 10s DB statement budget.
Limit authenticated requests to 60/minute/capability, burst 10; rate-limit failed
authentication before DB lookup to 30/minute/source, burst 10 using trusted ingress
addressing. Cap one in-flight state write per slot and four body buffers per
server process; reject excess work with generic 429/Retry-After rather than buffer
unbounded plaintext. These initial limits are reversible operator defaults, not
a claim that all deployments fit them; increasing them needs measured capacity.

Accept one complete JSON object with state `version` exactly integer 4, `serial`
a base-10 integer 0..MaxInt64 and `lineage` a canonical nonzero lowercase UUID.
Reject duplicate object keys at every level, trailing data, excessive nesting
(depth >128), malformed integers and invalid UTF-8. Reject top-level keys that
case-fold to version, serial or lineage unless they use the exact lowercase name;
Go-compatible Unicode case folding must not permit metadata shadowing. Other
unknown top-level and provider members remain retained without interpretation. Do not validate/echo provider-specific values. Client-side
state encryption needs a later reviewed metadata/replay design; do not guess its
lineage or decrypt with a job-supplied key. Pin compatibility tests to this subset.

The first valid snapshot establishes lineage. Later writes require that lineage
and strictly increasing serial; gaps are allowed. A repeat of the current exact
bytes with matching serial/lineage/SHA-256 is a 200 no-op only while the same live
owner/fence remains authorized. Different bytes at the same serial, lower serial
or changed lineage return 409 without changing state. After a later head commits,
replay of an older snapshot cannot restore it. Never trust the client checksum.
OpenTofu's own push checks can be forced off, so backend invariants remain strict.
[OpenTofu state push](https://opentofu.org/docs/cli/commands/state/push/)

Each accepted new snapshot gets a fresh server UUID and immutable metadata:
org/stack, lineage, serial, exact-byte SHA-256, size, server timestamp, source
run/job/fence and encryption schema version. Insert version, compare/update head
and insert `state.version.created` audit atomically. Failed auth, tamper, conflict
or audit insertion changes neither version nor head. Client retries create no
extra version or audit; current authorization is checked before replay success.
Do not infer successful infrastructure application from a state upload alone.

## Encrypted persistence, migrations and recovery

Use PostgreSQL bytea for bounded M1 ciphertext; object storage is deferred. Retain
ADR0003/0013 fresh per-version AES-256-GCM data key/nonces and independent wrapping
nonce. AAD uses authorized org, version UUID, purpose `state:<stack-UUID>` and
schema version 1. This binds ciphertext to both its stack and immutable version.
Wrap AAD also binds the operator key ID. Compute trusted digests after bounded
validation; encryption may occur before the short commit transaction, but recheck
authorization, owner/fence/head and replay rules under row locks before insert.
Decrypt only after tenant/job authorization, then verify AEAD, digest and length
before sending any bytes. Missing key, wrong context or tamper is an error, never
204 or partial plaintext. Clear transient plaintext/key buffers where practical;
Go memory zeroization and remote client disk behavior cannot be fully guaranteed.

Explicitly choose the mounted local provider for this bounded M1 deployment:
ADR0017 protected regular files, stable operator key IDs, no environment/default
key fallback. Before exposure, implement reviewed multi-key read/rewrap rotation
with one active write key, old read keys retained until every version is rewrapped,
and backup/restore verification. No plaintext database or image master key.
KMS remains a later provider substitution under the same envelope contract.
Never retire a key while any retained ciphertext or backup still requires it.

Reserve migration 00007 after ADR0018 stacks migration 00006 for a forced-RLS
state slot/head/reservation, retained lock history, state capability verifier/
bindings and missing state_versions metadata. Split later schema work further
if its tests/docs exceed the PR size limit; do not consume another owner's number.
The proposed state_slots row is PK(org_id,stack_id), nullable head_version_id,
last_fence bigint >=0 (0 only before first allocation), nullable reserved_run_id/
reserved_job_id, nullable reservation_status and nullable lock_id. Non-null status
is RESERVED, LOCKED, UNLOCK_REQUESTED or QUARANTINED; ownership fields are present
when reserved. Stack Update/Delete, while holding stack FOR UPDATE, must reject
`EXISTS (SELECT 1 FROM state_slots WHERE org_id=$1 AND stack_id=$2
AND reservation_status IS NOT NULL)`. Any unknown non-null status counts as active.
State acquisition holds stack FOR SHARE before slot FOR UPDATE and rejects
incomplete/archived stacks. Mutation handlers depend on this schema, with no
missing-table fallback. Head FKs include org/stack/version to prevent cross-stack
head substitution. Preserve
composite org FKs and unique `(org,stack,serial)`. Revoke runtime UPDATE/DELETE on
version content; retain SELECT/INSERT only. Rewrapping uses separately authorized
key-maintenance privileges limited to wrapped_dek/key_id, preserving content and
audit invariants. Audit's append-only trigger and runtime restrictions remain.
Existing opaque rows remain preserved and quarantined until a trusted
decrypt/validate/backfill procedure can establish their head. Schema migration
must not invent metadata or require keys merely to retain an opaque row. If any
retained versions lack verified head metadata, reads/writes fail with generic 503;
no-head is 204 only when no retained versions exist. Never reset legacy state to
empty. Downgrade must fail rather than discard post-upgrade metadata or versions.
Runtime roles cannot hard-delete history or stacks.

Rollback is a distinct trusted administrative restore operation, never DELETE or
an unlocked old-serial POST. Its internal arguments are stack UUID, source version
UUID, expected current version UUID and canonical idempotency UUID. Require a
current interactive admin, exact same-org/stack source, no nonterminal run, no
reservation/lock and independent evidence that no old process can resume. Serialize
membership -> stack -> state slot; invalidate old capabilities and advance fence.
Decrypt/authenticate the retained source, preserve its entire JSON content except
replacing root serial with current serial+1, retain established lineage, reseal as
a new version and atomically move head plus `state.restored` audit. Overflow denies.
An exact authorized restore replay returns its saved result; changed arguments
with the same key conflict. History remains intact; restored state does not undo
cloud side effects or approve an apply. No public restore RPC/CLI is approved
here; its human-facing contract requires a separate additive ADR before exposure.
Operator quarantine reconciliation also remains explicitly unbound pending review.

## Audit, privacy and acceptance gates

Audit capability issuance/revocation, first lock attachment, release intent,
trusted reservation release/quarantine, version creation, restore and rewrap with
fixed action and authorized actor/org/stack IDs. Run/job/version IDs are typed
metadata stored in dedicated columns only after an approved migration; never put
state, plan, configuration, lock descriptions, tokens, hashes of credentials,
SQL or provider diagnostics in audit payloads. Exact retries do not repeat audit.
Read access is counted with fixed metric labels; do not log state or resource
values. Prevent request/response dumping in middleware, ingress, traces, SDKs and
AI. Sensitive capability/envelope wrappers must redact normal formatting.

Publish tested slices below 500 changed lines each: (1) validation/lock metadata;
(2) state schema/RLS/append-only grants; (3) encrypted version/head storage;
(4) capability verifier/admission binding; (5) lock/replay/fence transitions;
(6) read/write HTTP protocol; (7) trusted release/recovery integration. Each slice
includes docs/tests and mandatory QA-SECURITY review. Do not expose a permissive
stub to make init pass. Every later proto addition needs an exact accepted ADR,
regenerated Go/Connect/TS and real-base Buf lint/build/breaking/wire checks.

Required evidence before WP-1.3 is DONE:
- >=70% business coverage, race/vet, safe-error/leak tests and full hosted CI,
  vulnerability/image scans and migration down/up with retained encrypted data.
- PostgreSQL 16 tests as non-owner/NOBYPASSRLS: both tenant directions, missing
  and pooled context reset, composite FKs, demotion/deletion and audit rollback.
- Two concurrent writers: exactly one admitted reservation, lock/fence owner,
  accepted serial/version and matching audit; stale/expired/revoked/wrong-job
  capabilities and guessed/replayed lock IDs never write or release another job.
- Dropped responses/retries at LOCK, POST and UNLOCK; duplicate bodies, older
  serial, changed lineage, overflow, chunked oversize and malformed/ambiguous JSON.
- Ciphertext-only persistence, exact-byte decrypt roundtrip, wrong tenant/stack/
  version AAD, tamper/unknown-key rejection, rewrap, restart and encrypted backup
  restore; corruption must never look like an absent state.
- Real pinned `tofu init` and an approved LocalStack plan/human-approve/apply using
  only job capabilities; malicious backend/env redirects denied, concurrent apply
  blocked, intermediate/final snapshots
  versioned, final unlock acknowledged then trusted quiescent release observed.
- Cancel/timeout/lost-ack/old-process races retain quarantine until proof; stale
  base state rejects BeginApply. No claim of exactly-once cloud effects.

WP-1.3 and the full M1 MVP stay incomplete until their respective CI acceptance
passes with real auth, runner, state and audit paths. Mock protocol tests alone
prove neither safe apply admission nor deployability.
