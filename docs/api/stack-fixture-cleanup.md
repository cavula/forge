# Test cleanup after stack archival

Migration 00006 revokes runtime hard DELETE on stacks. SQL-policy fixtures that
share a test database use DATABASE_URL's separately supplied migration owner
only for exact fixture-org teardown inside WithOrg, retaining FORCE RLS and
explicit org predicates. The helper rejects superuser/BYPASSRLS and requires
actual stack ownership; every substantive storage assertion still uses the
distinct nonowner runtime pool.

The auth login-flow test already creates its own random disposable database.
It relies on that existing database teardown rather than runtime row deletion.
No production credential, handler, policy, role grant or runtime query changes.

Real PostgreSQL 16 race tests pass the three affected auth/storage tests after
00006 in a separate disposable database; hosted CI and security review remain.
