import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// El navegador ve un único origen: Vite redirige /api a la API de NestJS, así no hay CORS
// y las cookies de sesión (SameSite=Strict) viajan en el mismo origen http://localhost:5173.
const apiProxy = {
  '/api': {
    target: 'http://localhost:3000',
    changeOrigin: false,
  },
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: apiProxy,
  },
  preview: {
    port: 5173,
    strictPort: true,
    proxy: apiProxy,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
    restoreMocks: true,
    testTimeout: 20000,
    hookTimeout: 20000,
  },
})
