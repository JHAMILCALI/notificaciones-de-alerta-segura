import { resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'
import { apiTarget, loadLabTls } from './config/lab-tls.ts'

// El navegador ve un único origen: Vite redirige /api a la API de NestJS, así no hay CORS
// y las cookies de sesión (SameSite=Strict) viajan en el mismo origen (http o https://localhost:5173).
// Con LAB_TLS=1 el origen es HTTPS con un certificado de mkcert (ver README); API_TARGET cambia el destino.
const tls = loadLabTls(process.env, resolve(import.meta.dirname, '../..'))
const apiProxy = {
  '/api': {
    target: apiTarget(process.env, tls !== null),
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
    ...(tls === null ? {} : { https: tls }),
  },
  preview: {
    port: 5173,
    strictPort: true,
    proxy: apiProxy,
    ...(tls === null ? {} : { https: tls }),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}', 'config/**/*.test.ts'],
    css: false,
    restoreMocks: true,
    testTimeout: 20000,
    hookTimeout: 20000,
  },
})
