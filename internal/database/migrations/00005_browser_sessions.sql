-- +goose Up
CREATE TABLE browser_sessions (
 id uuid PRIMARY KEY,
 credential_hash bytea NOT NULL UNIQUE CHECK (octet_length(credential_hash) = 32),
 issuer text NOT NULL CHECK (length(issuer) > 0),
 subject text NOT NULL CHECK (length(subject) > 0),
 csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 CHECK (expires_at > created_at AND expires_at <= created_at + interval '8 hours')
);
CREATE INDEX browser_sessions_expiry_id ON browser_sessions (expires_at, id);
ALTER TABLE browser_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE browser_sessions FORCE ROW LEVEL SECURITY;
-- Canonical lowercase hex comparison denies malformed GUCs without decoding.
CREATE POLICY browser_session_select ON browser_sessions FOR SELECT TO forge_app
 USING (encode(credential_hash, 'hex') = nullif(current_setting('forge.browser_session_hash', true), ''));
CREATE POLICY browser_session_insert ON browser_sessions FOR INSERT TO forge_app
 WITH CHECK (encode(credential_hash, 'hex') = nullif(current_setting('forge.browser_session_hash', true), ''));
CREATE POLICY browser_session_delete ON browser_sessions FOR DELETE TO forge_app
 USING (encode(credential_hash, 'hex') = nullif(current_setting('forge.browser_session_hash', true), ''));
GRANT SELECT, DELETE ON browser_sessions TO forge_app;
GRANT INSERT (id, credential_hash, issuer, subject, csrf_hash, expires_at)
 ON browser_sessions TO forge_app;

ALTER TABLE auth_security_events DROP CONSTRAINT auth_security_events_action_check;
ALTER TABLE auth_security_events ADD CONSTRAINT auth_security_events_action_check
 CHECK (action IN ('login_flow.created', 'login_flow.consumed',
 'browser_session.created', 'browser_session.revoked', 'browser_session.replaced'));

-- +goose Down
DROP TABLE browser_sessions;
ALTER TABLE auth_security_events DROP CONSTRAINT auth_security_events_action_check;
-- Preserve immutable historical session events; enforce the old allowlist for
-- new writes. Reapplying Up validates all retained events under the wider list.
ALTER TABLE auth_security_events ADD CONSTRAINT auth_security_events_action_check
 CHECK (action IN ('login_flow.created', 'login_flow.consumed')) NOT VALID;
