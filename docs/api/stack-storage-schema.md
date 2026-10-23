# Stack storage schema

Migration 00006 implements ADR0018's approved storage refinement. Legacy rows
retain unknown NULL repository/branch/directory/version/environment and creation
time. Revision starts at 1; full validated replacement repairs configuration but
cannot invent its original creation time. New inserts default to their actual
transaction timestamp. Empty environment is [], distinct from legacy NULL.

The SQL CHECK permits all five legacy NULL fields or structurally complete bounded
configuration. URL/ref/path/version/environment semantics still require approved
Go validation before writes; SQL shape alone never means runnable or authorized.
Store sorted non-secret {name,value} environment entries only. No credentials,
secret payloads, runner invocation, handlers or audit behavior are added here.

Archived rows keep their name under the existing unfiltered UNIQUE(org_id,name),
all references and history. Runtime hard DELETE is revoked. Ordinary CRUD must
exclude deleted_at and serialize membership -> stack locks, expected revisions
and audit. Admission uses stack FOR SHARE and rejects archived/incomplete rows.
Mutation guards depend on migration 00007 state_slots and must reject every
non-NULL reservation_status plus nonterminal/unknown runs, with no fallback for
a missing table. Those storage/admission paths remain separate work.

Down first validates that every row has untouched legacy metadata. PostgreSQL
validates a CHECK across all tuples even when FORCE RLS hides them from owner
SELECT. Configured, archived or newly timestamped rows make downgrade fail
atomically; no column or name reservation is silently lost. After real writes,
rollback needs a separately reviewed export/restore plan. Untouched legacy rows
support lossless upgrade/down/up. Down restores the original DELETE grant only
after proving that safe state.

TestStackStorageSchema creates and drops its own random disposable database using
DATABASE_URL's non-superuser migration owner with CREATEDB. TEST_DATABASE_URL
supplies the distinct nonowner/NOBYPASSRLS role; its database is replaced only in
the test's private configuration. Application assertions use WithOrg and explicit
predicates. No shared database is migrated or rolled back by this test.

Real PostgreSQL 16 race validation passes the full upgrade/down/up/isolation
test and the prerequisite auth/storage fixture cleanup checks after 00006.
Hosted CI and QA-SECURITY acceptance remain pending.
