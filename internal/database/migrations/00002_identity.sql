-- +goose Up
ALTER TABLE users ADD COLUMN role text NOT NULL DEFAULT 'reader'
 CHECK (role IN ('admin', 'writer', 'reader'));

CREATE TABLE team_memberships (
 org_id uuid NOT NULL, team_id uuid NOT NULL, user_id uuid NOT NULL,
 PRIMARY KEY (org_id, team_id, user_id),
 FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id),
 FOREIGN KEY (org_id, user_id) REFERENCES users(org_id, id)
);
ALTER TABLE team_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON team_memberships
 USING (org_id = nullif(current_setting('forge.org_id', true), '')::uuid)
 WITH CHECK (org_id = nullif(current_setting('forge.org_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON team_memberships TO forge_app;

-- +goose Down
DROP TABLE team_memberships;
ALTER TABLE users DROP COLUMN role;
