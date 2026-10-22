-- Local development only. Production must provision an independently authenticated
-- runtime role and keep migration-owner credentials out of application processes.
CREATE ROLE forge_app LOGIN PASSWORD 'forge-dev-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
