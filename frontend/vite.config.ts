import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const GATEWAY = process.env.GUARDRAIL_GATEWAY_URL ?? 'http://127.0.0.1:8000'

// The dashboard is served under /app/ - by the Vite dev server during
// development and by the gateway itself after `npm run build`.
export default defineConfig({
  base: '/app/',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    // Same-origin API calls in development: no CORS, no credentials in URLs.
    proxy: {
      '/v1': { target: GATEWAY, changeOrigin: false },
      '/health': { target: GATEWAY, changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
  },
})
