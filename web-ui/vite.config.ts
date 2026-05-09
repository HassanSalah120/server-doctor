import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ command }) => ({
  plugins: [react()],
  // Use root paths in local dev so routes like /reports/:id work directly.
  // Keep /static/spa/ for production static serving by FastAPI.
  base: command === 'serve' ? '/' : '/static/spa/',
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8765',
    },
  },
  build: {
    outDir: '../src/server_doctor/web/static/spa',
    emptyOutDir: true,
    assetsDir: 'assets',
  },
}))
