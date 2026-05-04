import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The decompiler worker imports a wasm-loader ES module emitted by
// emscripten — vite must NOT try to optimize-bundle it (the loader
// fetches the .wasm sibling at runtime). Marking the dist as
// excluded from optimization preserves emscripten's native loading
// path while still letting the worker `import` from it.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Mirror tsconfig.json's `@/*` path mapping. tsconfig paths
      // are TS-only; vite needs its own resolver entry.
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    host: true,
    headers: {
      // SharedArrayBuffer / cross-origin isolation. Not strictly
      // required for our single-threaded wasm build, but harmless and
      // we'll need them if/when we enable -pthread in the wasm later.
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
    fs: {
      // Allow serving symlinks pointing outside the project root —
      // public/decompiler and public/specs link to ../decompiler-wasm/dist
      // and ../specs/dist respectively.
      strict: false,
    },
    watch: {
      // Lima's bind-mount doesn't propagate inotify events from the
      // host, so vite never sees host-side edits. Polling is the only
      // reliable file-change signal in that environment. ~250ms is
      // imperceptible for HMR and barely registers on CPU.
      usePolling: true,
      interval: 250,
    },
  },
  optimizeDeps: {
    exclude: ["pyre_decompiler.js"],
  },
  worker: {
    format: "es",
  },
  build: {
    target: "es2022",
    sourcemap: true,
  },
});
