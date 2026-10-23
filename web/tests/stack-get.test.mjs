import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary, fromJson, toJson } from "@bufbuild/protobuf";
import { Engine } from "../src/gen/forge/v1/entities_pb.ts";
import { GetStackRequestSchema, GetStackResponseSchema, file_forge_v1_stack_get } from "../src/gen/forge/v1/stack_get_pb.ts";

test("GetStack request carries only the stack ID at field one", () => {
  assert.equal(GetStackRequestSchema.typeName, "forge.v1.GetStackRequest");
  assert.deepEqual(GetStackRequestSchema.fields.map(({ name, number }) => [name, number]), [["id", 1]]);
  assert.equal(GetStackRequestSchema.fields[0].scalar, 9);
  const request = create(GetStackRequestSchema, { id: "20000000-0000-0000-0000-000000000001" });
  const wire = toBinary(GetStackRequestSchema, request);
  assert.deepEqual([...wire], [10, 36, ...Buffer.from(request.id)]);
  assert.deepEqual(fromBinary(GetStackRequestSchema, wire), request);
  assert.deepEqual(toJson(GetStackRequestSchema, request), { id: request.id });
  assert.deepEqual(fromJson(GetStackRequestSchema, toJson(GetStackRequestSchema, request)), request);
});

test("GetStack response preserves Stack metadata, non-secret configuration and exact revision", () => {
  const response = create(GetStackResponseSchema, { stack: {
    id: "20000000-0000-0000-0000-000000000001", orgId: "10000000-0000-0000-0000-000000000001",
    name: "example", repositoryUrl: "https://git.example/team/infrastructure", branch: "main",
    workingDirectory: "environments/dev", engine: Engine.OPENTOFU, engineVersion: "1.10.6",
    createdAt: { seconds: 1792713600n, nanos: 123000000 }, configurationRevision: 9007199254740993n,
    environmentVariables: [{ name: "TF_VAR_display_name", value: "München 東京" }],
  } });
  assert.deepEqual(fromBinary(GetStackResponseSchema, toBinary(GetStackResponseSchema, response)), response);
  const json = toJson(GetStackResponseSchema, response);
  assert.equal(json.stack.configurationRevision, "9007199254740993");
  assert.deepEqual(fromJson(GetStackResponseSchema, json), response);
  assert.equal(GetStackResponseSchema.typeName, "forge.v1.GetStackResponse");
  assert.deepEqual(GetStackResponseSchema.fields.map(({ name, number }) => [name, number]), [["stack", 1]]);
  assert.equal(GetStackResponseSchema.fields[0].message.typeName, "forge.v1.Stack");
});

test("GetStack retains absent response presence and introduces no service", () => {
  const empty = create(GetStackResponseSchema);
  assert.equal(fromBinary(GetStackResponseSchema, new Uint8Array()).stack, undefined);
  assert.deepEqual(toJson(GetStackResponseSchema, empty), {});
  assert.deepEqual(fromJson(GetStackResponseSchema, {}), empty);
  assert.deepEqual(file_forge_v1_stack_get.messages.map(({ typeName }) => typeName), [
    "forge.v1.GetStackRequest", "forge.v1.GetStackResponse",
  ]);
  assert.equal(file_forge_v1_stack_get.services.length, 0);
});
