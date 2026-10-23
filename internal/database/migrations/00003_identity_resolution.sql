-- +goose Up
-- This policy permits verified-principal lookup only; it never authorizes
-- organization resources or user mutations. Tenant RLS remains enabled/forced.
CREATE POLICY verified_identity_lookup ON users FOR SELECT TO forge_app
 USING (issuer = nullif(current_setting('forge.auth_issuer', true), '')
    AND subject = nullif(current_setting('forge.auth_subject', true), ''));

-- +goose Down
DROP POLICY verified_identity_lookup ON users;
