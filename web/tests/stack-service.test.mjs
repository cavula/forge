import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary, fromJson, toJson } from "@bufbuild/protobuf";
import { StackService, file_forge_v1_stack_service } from "../src/gen/forge/v1/stack_service_pb.ts";

test("StackService declares only the approved unary lookup and stable message types", () => {
  assert.equal(StackService.typeName, "forge.v1.StackService");
  assert.equal(file_forge_v1_stack_service.messages.length, 0);
  assert.equal(file_forge_v1_stack_service.services.length, 1);
  assert.equal(StackService.methods.length, 1);
  const method = StackService.method.getStack;
  assert.equal(method.name, "GetStack");
  assert.equal(method.methodKind, "unary");
  assert.equal(method.input.typeName, "forge.v1.GetStackRequest");
  assert.equal(method.output.typeName, "forge.v1.GetStackResponse");
  assert.deepEqual(method.input.fields.map(({ name, number }) => [name, number]), [["id", 1]]);
  assert.equal(method.output.fields[0].message.typeName, "forge.v1.Stack");
  const request = create(method.input, { id: "20000000-0000-0000-0000-000000000001" });
  const response = create(method.output, { stack: { id: request.id, configurationRevision: 9007199254740993n } });
  for (const [schema, message] of [[method.input, request], [method.output, response]]) {
    assert.deepEqual(fromBinary(schema, toBinary(schema, message)), message);
    assert.deepEqual(fromJson(schema, toJson(schema, message)), message);
  }
  assert.equal(toJson(method.output, response).stack.configurationRevision, "9007199254740993");
});
