import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Production build output goes to ../static so the gateway can serve the SPA.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../static",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API and WebSocket traffic to the gateway during development.
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/ws": { target: "ws://localhost:8080", ws: true },
    },
  },
});
