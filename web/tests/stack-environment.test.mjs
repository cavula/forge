import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { StackEnvironmentVariableSchema, file_forge_v1_stack_environment } from "../src/gen/forge/v1/stack_environment_pb.ts";

test("stack environment preserves non-secret Unicode values on the wire", () => {
  const variable = create(StackEnvironmentVariableSchema, {
    name: "TF_VAR_display_name",
    value: "München 東京",
  });
  assert.deepEqual(fromBinary(StackEnvironmentVariableSchema, toBinary(StackEnvironmentVariableSchema, variable)), variable);
});

test("stack environment exposes only the approved fields and no RPC", () => {
  assert.equal(StackEnvironmentVariableSchema.typeName, "forge.v1.StackEnvironmentVariable");
  assert.deepEqual(StackEnvironmentVariableSchema.fields.map(({ name, number, fieldKind, scalar }) =>
    ({ name, number, fieldKind, scalar })), [
    { name: "name", number: 1, fieldKind: "scalar", scalar: 9 },
    { name: "value", number: 2, fieldKind: "scalar", scalar: 9 },
  ]);
  assert.equal(file_forge_v1_stack_environment.services.length, 0);
});
