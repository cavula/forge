import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { Role } from "../src/gen/forge/v1/entities_pb.ts";

// Generated imports are extensionless; these tests execute TypeScript directly.
const hook = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "./entities_pb" && context.parentURL?.endsWith("/identity_get_current_user_pb.ts")) {
      return nextResolve("./entities_pb.ts", context);
    }
    return nextResolve(specifier, context);
  },
});
const { GetCurrentUserRequestSchema, GetCurrentUserResponseSchema } = await import("../src/gen/forge/v1/identity_get_current_user_pb.ts");
hook.deregister();

test("current-user response preserves resolved membership over the wire", () => {
  const response = create(GetCurrentUserResponseSchema, {
    user: {
      id: "20000000-0000-0000-0000-000000000001",
      orgId: "10000000-0000-0000-0000-000000000001",
      oidcIssuer: "https://issuer.example",
      oidcSubject: "subject-1",
      displayName: "Example user",
      role: Role.READER,
    },
  });
  assert.deepEqual(fromBinary(GetCurrentUserResponseSchema, toBinary(GetCurrentUserResponseSchema, response)), response);
});

test("current-user request cannot assert an organization or role", () => {
  assert.deepEqual(GetCurrentUserRequestSchema.fields, []);
  const request = create(GetCurrentUserRequestSchema);
  assert.equal(toBinary(GetCurrentUserRequestSchema, request).length, 0);
});
