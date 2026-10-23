-- +goose Up
CREATE TABLE login_flows (
 id uuid PRIMARY KEY,
 state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
 binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes',
 ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 0),
 nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
 wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) > 0),
 key_id text NOT NULL CHECK (length(key_id) > 0),
 CHECK (expires_at = created_at + interval '10 minutes')
);
CREATE INDEX login_flows_expiry_id ON login_flows (expires_at, id);
ALTER TABLE login_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_flows FORCE ROW LEVEL SECURITY;
-- encode produces canonical lowercase hex; malformed/partial GUCs simply fail
-- equality instead of being decoded. Both independent proofs are mandatory.
CREATE POLICY login_flow_select ON login_flows FOR SELECT TO forge_app
 USING (encode(state_hash, 'hex') = nullif(current_setting('forge.login_state_hash', true), '')
    AND encode(binding_hash, 'hex') = nullif(current_setting('forge.login_binding_hash', true), ''));
CREATE POLICY login_flow_insert ON login_flows FOR INSERT TO forge_app
 WITH CHECK (encode(state_hash, 'hex') = nullif(current_setting('forge.login_state_hash', true), '')
         AND encode(binding_hash, 'hex') = nullif(current_setting('forge.login_binding_hash', true), ''));
CREATE POLICY login_flow_delete ON login_flows FOR DELETE TO forge_app
 USING (encode(state_hash, 'hex') = nullif(current_setting('forge.login_state_hash', true), '')
    AND encode(binding_hash, 'hex') = nullif(current_setting('forge.login_binding_hash', true), ''));
GRANT SELECT, DELETE ON login_flows TO forge_app;
GRANT INSERT (id, state_hash, binding_hash, ciphertext, nonce, wrapped_dek, key_id)
 ON login_flows TO forge_app;

CREATE TABLE auth_security_events (
 id uuid PRIMARY KEY,
 occurred_at timestamptz NOT NULL DEFAULT now(),
 action text NOT NULL CHECK (action IN ('login_flow.created', 'login_flow.consumed')),
 outcome text NOT NULL CHECK (outcome = 'success')
);
ALTER TABLE auth_security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY auth_security_event_insert ON auth_security_events FOR INSERT TO forge_app
 WITH CHECK (true);
CREATE TRIGGER auth_security_events_append_only
 BEFORE UPDATE OR DELETE OR TRUNCATE ON auth_security_events
 FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();
GRANT INSERT (id, action, outcome) ON auth_security_events TO forge_app;

-- +goose Down
DROP TABLE auth_security_events, login_flows;
