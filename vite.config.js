import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  root: fileURLToPath(new URL("./web", import.meta.url)),
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/health": "http://127.0.0.1:8000",
      "/score": "http://127.0.0.1:8000",
    },
  },
  build: {
    outDir: fileURLToPath(new URL("./phishguardz/static", import.meta.url)),
    emptyOutDir: true,
  },
});
