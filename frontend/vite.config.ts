import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // libsodium-wrappers-sumo's ESM build has a broken relative import
      // ("./libsodium-sumo.mjs") that doesn't resolve under normal bundling - its
      // CJS build uses a proper package import instead, so use that one here.
      "libsodium-wrappers-sumo": path.resolve(
        dirname,
        "node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js",
      ),
    },
  },
  server: {
    host: true,
    port: 5173,
  },
});
