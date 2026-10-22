import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { OrgSchema } from "../src/gen/forge/v1/org_pb.ts";
test("organization contract survives protobuf wire roundtrip", () => {
  const org = create(OrgSchema, { id: "10000000-0000-0000-0000-000000000001", name: "Example" });
  assert.deepEqual(fromBinary(OrgSchema, toBinary(OrgSchema, org)), org);
});
