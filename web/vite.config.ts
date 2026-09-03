import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Build output lands directly in internal/webui/dist so `go build` embeds
// it with no separate copy step. The dev server proxies API/WS calls to
// the Go backend so `go run ./cmd/aperture` and `npm run dev` can run side
// by side without CORS.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/ws': {
        target: 'ws://127.0.0.1:8080',
        ws: true,
      },
    },
  },
})
