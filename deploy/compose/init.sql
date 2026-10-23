-- Local development only. Production must provision an independently authenticated
-- runtime role and keep migration-owner credentials out of application processes.
CREATE ROLE forge_owner LOGIN PASSWORD 'forge-owner-dev-only' NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOREPLICATION CREATEDB;
ALTER DATABASE forge OWNER TO forge_owner;
CREATE ROLE forge_app LOGIN PASSWORD 'forge-dev-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
-- The maintenance bootstrap account is used only for initialization. The owner
-- remains subject to FORCE RLS; CREATEDB supports Temporal's evaluation databases.
