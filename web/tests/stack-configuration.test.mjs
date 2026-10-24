import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary, fromJson, toJson } from "@bufbuild/protobuf";
import { Engine } from "../src/gen/forge/v1/entities_pb.ts";
import { StackConfigurationSchema, file_forge_v1_stack_configuration } from "../src/gen/forge/v1/stack_configuration_pb.ts";

test("mutable stack configuration preserves every approved field on the wire", () => {
  const configuration = create(StackConfigurationSchema, {
    name: "example", repositoryUrl: "https://git.example/team/infrastructure",
    branch: "main", workingDirectory: "environments/dev", engine: Engine.OPENTOFU,
    engineVersion: "1.10.6", environmentVariables: [{ name: "TF_VAR_display_name", value: "München 東京" }],
  });
  assert.deepEqual(fromBinary(StackConfigurationSchema, toBinary(StackConfigurationSchema, configuration)), configuration);
  assert.deepEqual(fromJson(StackConfigurationSchema, toJson(StackConfigurationSchema, configuration)), configuration);
});

test("configuration excludes server identity, tenant, timestamp and revision metadata", () => {
  assert.equal(StackConfigurationSchema.typeName, "forge.v1.StackConfiguration");
  assert.deepEqual(StackConfigurationSchema.fields.map(({ name, number }) => [name, number]), [
    ["name", 1], ["repository_url", 2], ["branch", 3], ["working_directory", 4],
    ["engine", 5], ["engine_version", 6], ["environment_variables", 7],
  ]);
  assert.equal(StackConfigurationSchema.fields[4].enum.typeName, "forge.v1.Engine");
  assert.equal(StackConfigurationSchema.fields[6].fieldKind, "list");
  assert.equal(StackConfigurationSchema.fields[6].message.typeName, "forge.v1.StackEnvironmentVariable");
  assert.equal(file_forge_v1_stack_configuration.services.length, 0);
});
