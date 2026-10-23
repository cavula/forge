# ADR 0017: Protected mounted local master-key file

Status: Accepted by ARCHITECT role on 2026-10-23 for the bounded loader slice;
independent QA-SECURITY and passing CI remain gates.
Owner: CORE-BACKEND. Scope: WP-1.3 / WP-1.8 local-provider configuration only.
Dependencies: ADR0003/0013 and the local envelope primitive.

`LoadLocalKeyFile(keyID, absolutePath)` explicitly selects one configured key ID
and canonical absolute file path; there is no environment fallback, generated key,
automatic reload or application/endpoint binding. The file contains exactly 32
binary bytes with no text decoding or trimming; an extra newline is rejected.
The loader copies the key through `NewLocalKey` and clears its temporary read buffer.
Errors use only generic `ErrInvalidKey`, without paths, IDs or key material.

Target Linux Docker/Kubernetes file mounts; support macOS for local development.
Other hosts do not provide this loader. Require effective-UID ownership and mode
0400 or 0600. Reject every symlink path component, directories and special files.
Use descriptor-relative nofollow opens, validate/read the same descriptor with a
33-byte bound, compare identity/permissions/size/timestamps after reading, then
rewalk the path and compare the resulting file identity and metadata.

Operators provision an owner-only stable regular file outside the image, database
and source tree, then mount it read-only at the configured path. Parent directories
must resist untrusted writes; ACLs and filesystem trust remain provisioning duties.
Kubernetes projected Secret symlink paths are deliberately unsupported: provision
an owned 0400/0600 regular file on a dedicated volume or stable file mount instead.
The loader never falls back to weaker permissions. Observed read/replacement races
fail closed; no userspace check makes hostile concurrent writes or changes after
the final check atomic. No watcher or in-place key rotation is implied.

Acceptance evidence: real temporary-file round trips, permission/type/size and
symlink rejection, bounded/redacted read errors, deterministic file/ancestor
replacement and mutation tests, race tests and business-logic coverage >=70%.
This slice does not finish a work package. Before state/secret endpoints ship,
ADR0013 still requires reviewed multi-key rewrap/rotation and persistence/tenant
authorization tests, plus KMS or an explicit deployed local-provider choice.
