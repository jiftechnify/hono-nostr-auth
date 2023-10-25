import { build, emptyDir } from "https://deno.land/x/dnt@0.38.1/mod.ts";

await emptyDir('./npm');
await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  shims: {
    deno: true,
    crypto: true,
  },
  package: {
    name: "hono-nostr-auth",
    version: Deno.args[0],
    description: "Nostr HTTP auth (NIP-98) middleware for Hono",
    license: "MIT",
    repository: {
      type: "git",
      url: "ssh://git@github.com/jiftechnify/hono-nostr-auth.git",
    },
    bugs: {
      url: "https://github.com/jiftechnify/hono-nostr-auth/issues",
    },
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  }
});
