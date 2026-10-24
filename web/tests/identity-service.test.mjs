import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

// Resolve only this generated import chain when testing TypeScript directly.
const hook = registerHooks({
  resolve(specifier, context, nextResolve) {
    const expected = new Map([
      ["./identity_get_current_user_pb", "/identity_service_pb.ts"],
      ["./entities_pb", "/identity_get_current_user_pb.ts"],
    ]);
    if (expected.has(specifier) && context.parentURL?.endsWith(expected.get(specifier))) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
});
const { IdentityService } = await import("../src/gen/forge/v1/identity_service_pb.ts");
hook.deregister();

test("identity service exposes only the approved unary membership lookup", () => {
  assert.equal(IdentityService.typeName, "forge.v1.IdentityService");
  assert.equal(IdentityService.methods.length, 1);
  const method = IdentityService.method.getCurrentUser;
  assert.equal(method.name, "GetCurrentUser");
  assert.equal(method.methodKind, "unary");
  assert.equal(method.input.typeName, "forge.v1.GetCurrentUserRequest");
  assert.equal(method.input.fields.length, 0);
  assert.equal(method.output.typeName, "forge.v1.GetCurrentUserResponse");
  assert.equal(method.output.fields[0].name, "user");
});
