import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // In local dev, proxy /api/* → FastAPI on :8000
      // This lets the frontend call /api/metrics instead of http://localhost:8000/metrics
      // and avoids CORS issues in development
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  }
})
