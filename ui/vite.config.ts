import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The app is hosted at /security/ in production (Apache reverse proxy →
// Express on 127.0.0.1:3046, both prefixed). Vite's `base` makes the
// generated asset URLs already include the prefix.
//
// In dev (`npm run dev`), the dev server proxies /security/api and
// /security/auth to the running service so cookies/sessions work the
// same way as they will in prod.
export default defineConfig({
  base: "/security/",
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/security/api": "http://127.0.0.1:3046",
      "/security/auth": "http://127.0.0.1:3046",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
