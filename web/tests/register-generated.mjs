import { registerHooks } from "node:module";

// Node executes generated TypeScript directly; Buf emits extensionless imports.
const generatedRoot = new URL("../src/gen/", import.meta.url).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (context.parentURL?.startsWith(generatedRoot) && /^\.{1,2}\/.*_pb$/.test(specifier)) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
});
