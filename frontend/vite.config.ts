import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Standard React + TS Vite setup. No proxy is configured yet because
// the current data source reads a static JSON file from /public.
// When the FastAPI backend exists, add a `server.proxy` entry here
// so `/api/*` requests are forwarded during development.
export default defineConfig({
  plugins: [react()],
});
