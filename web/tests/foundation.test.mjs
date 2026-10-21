import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { OrgSchema, SecretSchema } from "../src/gen/forge/v1/entities_pb.ts";
test("organization contract survives protobuf wire roundtrip", () => {
  const org = create(OrgSchema, { id: "10000000-0000-0000-0000-000000000001", name: "Example" });
  assert.deepEqual(fromBinary(OrgSchema, toBinary(OrgSchema, org)), org);
});
test("secret public contract exposes metadata only", () => {
  const names = SecretSchema.fields.map((field) => field.name);
  for (const forbidden of ["value", "plaintext", "ciphertext", "wrapped_dek"]) {
    assert.ok(!names.includes(forbidden));
  }
  assert.ok(names.includes("org_id"));
});
