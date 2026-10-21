-- +goose Up
CREATE TABLE orgs (
 id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
 org_id uuid NOT NULL REFERENCES orgs(id), id uuid NOT NULL, issuer text NOT NULL, subject text NOT NULL,
 display_name text NOT NULL, PRIMARY KEY(org_id,id), UNIQUE(org_id,issuer,subject)
);
CREATE TABLE teams (
 org_id uuid NOT NULL REFERENCES orgs(id), id uuid NOT NULL, name text NOT NULL,
 PRIMARY KEY(org_id,id), UNIQUE(org_id,name)
);
CREATE TABLE stacks (
 org_id uuid NOT NULL REFERENCES orgs(id), id uuid NOT NULL, name text NOT NULL,
 engine text NOT NULL DEFAULT 'opentofu' CHECK(engine IN ('opentofu','terraform','ansible')),
 PRIMARY KEY(org_id,id), UNIQUE(org_id,name)
);
CREATE TABLE runs (
 org_id uuid NOT NULL, id uuid NOT NULL, stack_id uuid NOT NULL,
 status text NOT NULL DEFAULT 'QUEUED', created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(org_id,id), FOREIGN KEY(org_id,stack_id) REFERENCES stacks(org_id,id)
);
-- State and secrets store only envelope-encrypted bytes, never plaintext.
CREATE TABLE state_versions (
 org_id uuid NOT NULL, id uuid NOT NULL, stack_id uuid NOT NULL, serial bigint NOT NULL CHECK(serial >= 0),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) > 0), wrapped_dek bytea NOT NULL,
 nonce bytea NOT NULL CHECK(octet_length(nonce) = 12), key_id text NOT NULL,
 PRIMARY KEY(org_id,id), UNIQUE(org_id,stack_id,serial),
 FOREIGN KEY(org_id,stack_id) REFERENCES stacks(org_id,id)
);
CREATE TABLE policies (
 org_id uuid NOT NULL REFERENCES orgs(id), id uuid NOT NULL, name text NOT NULL, source text NOT NULL,
 PRIMARY KEY(org_id,id), UNIQUE(org_id,name)
);
CREATE TABLE secrets (
 org_id uuid NOT NULL REFERENCES orgs(id), id uuid NOT NULL, name text NOT NULL,
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) > 0), wrapped_dek bytea NOT NULL,
 nonce bytea NOT NULL CHECK(octet_length(nonce) = 12), key_id text NOT NULL,
 PRIMARY KEY(org_id,id), UNIQUE(org_id,name)
);
CREATE TABLE audit_events (
 org_id uuid NOT NULL REFERENCES orgs(id), id uuid NOT NULL, actor_id uuid,
 stack_id uuid, action text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(org_id,id), FOREIGN KEY(org_id,actor_id) REFERENCES users(org_id,id),
 FOREIGN KEY(org_id,stack_id) REFERENCES stacks(org_id,id)
);
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['orgs','users','teams','stacks','runs','state_versions','policies','secrets','audit_events'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (%I = nullif(current_setting(''forge.org_id'', true), '''')::uuid) WITH CHECK (%I = nullif(current_setting(''forge.org_id'', true), '''')::uuid)',
   t, CASE WHEN t = 'orgs' THEN 'id' ELSE 'org_id' END, CASE WHEN t = 'orgs' THEN 'id' ELSE 'org_id' END);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'audit events are append-only';
END $$;
-- +goose StatementEnd
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
 FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();
GRANT USAGE ON SCHEMA public TO forge_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON orgs, users, teams, stacks, runs, state_versions, policies, secrets TO forge_app;
GRANT SELECT, INSERT ON audit_events TO forge_app;

-- +goose Down
DROP TABLE audit_events, secrets, policies, state_versions, runs, stacks, teams, users, orgs;
DROP FUNCTION reject_audit_mutation();
