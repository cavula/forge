import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { create, fromBinary, toBinary, fromJson, toJson } from "@bufbuild/protobuf";

const hook = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "./stack_environment_pb" && context.parentURL?.endsWith("/entities_pb.ts")) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
});
const { StackSchema, Engine } = await import("../src/gen/forge/v1/entities_pb.ts");
hook.deregister();

test("Stack preserves the original nine fields and appends only approved metadata", () => {
  assert.deepEqual(StackSchema.fields.map(({ name, number }) => [name, number]), [
    ["id", 1], ["org_id", 2], ["name", 3], ["repository_url", 4], ["branch", 5],
    ["working_directory", 6], ["engine", 7], ["engine_version", 8], ["created_at", 9],
    ["environment_variables", 10], ["configuration_revision", 11],
  ]);
  const environment = StackSchema.fields[9];
  assert.equal(environment.fieldKind, "list");
  assert.equal(environment.message.typeName, "forge.v1.StackEnvironmentVariable");
  const revision = StackSchema.fields[10];
  assert.equal(revision.fieldKind, "scalar");
  assert.equal(revision.scalar, 4);
});

test("Stack wire and JSON retain non-secret environment and revisions beyond safe Number", () => {
  const stack = create(StackSchema, {
    id: "20000000-0000-0000-0000-000000000001", name: "example", engine: Engine.OPENTOFU,
    environmentVariables: [{ name: "TF_VAR_display_name", value: "München 東京" }],
    configurationRevision: 9007199254740993n,
  });
  assert.deepEqual(fromBinary(StackSchema, toBinary(StackSchema, stack)), stack);
  assert.equal(toJson(StackSchema, stack).configurationRevision, "9007199254740993");
  assert.deepEqual(fromJson(StackSchema, toJson(StackSchema, stack)), stack);
  assert.equal(typeof stack.configurationRevision, "bigint");
});
