-- +goose Up
ALTER TABLE stacks
 ADD COLUMN repository_url text,
 ADD COLUMN branch text,
 ADD COLUMN working_directory text,
 ADD COLUMN engine_version text,
 ADD COLUMN environment_variables jsonb,
 ADD COLUMN created_at timestamptz,
 ADD COLUMN deleted_at timestamptz,
 ADD COLUMN configuration_revision bigint NOT NULL DEFAULT 1,
 ADD CONSTRAINT stacks_revision_positive CHECK (configuration_revision > 0),
 ADD CONSTRAINT stacks_configuration_shape CHECK (
  (repository_url IS NULL AND branch IS NULL AND working_directory IS NULL
   AND engine_version IS NULL AND environment_variables IS NULL)
  OR
  (repository_url IS NOT NULL AND branch IS NOT NULL AND working_directory IS NOT NULL
   AND engine_version IS NOT NULL AND environment_variables IS NOT NULL
   AND octet_length(name) BETWEEN 1 AND 100
   AND octet_length(repository_url) BETWEEN 1 AND 2048
   AND octet_length(branch) BETWEEN 1 AND 255
   AND octet_length(working_directory) BETWEEN 1 AND 512
   AND octet_length(engine_version) BETWEEN 1 AND 64
   AND CASE WHEN jsonb_typeof(environment_variables)='array'
    THEN jsonb_array_length(environment_variables)<=64
     AND octet_length(environment_variables::text)<=65536 ELSE false END)
 );
-- Set the default only after adding the nullable column: legacy history stays NULL.
ALTER TABLE stacks ALTER COLUMN created_at SET DEFAULT now();
REVOKE DELETE ON stacks FROM forge_app;

-- +goose Down
-- Constraint validation checks every tuple, independent of owner RLS visibility.
-- Abort atomically rather than lose configuration/history or resurrect an archive.
ALTER TABLE stacks ADD CONSTRAINT stacks_downgrade_safe CHECK (
 repository_url IS NULL AND branch IS NULL AND working_directory IS NULL
 AND engine_version IS NULL AND environment_variables IS NULL
 AND created_at IS NULL AND deleted_at IS NULL AND configuration_revision=1
);
ALTER TABLE stacks
 DROP COLUMN repository_url, DROP COLUMN branch, DROP COLUMN working_directory,
 DROP COLUMN engine_version, DROP COLUMN environment_variables,
 DROP COLUMN created_at, DROP COLUMN deleted_at, DROP COLUMN configuration_revision;
GRANT DELETE ON stacks TO forge_app;
