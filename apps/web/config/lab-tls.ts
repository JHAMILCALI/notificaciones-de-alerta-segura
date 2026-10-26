import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

export interface LabTls {
  cert: Buffer
  key: Buffer
}

export interface LabTlsEnv {
  LAB_TLS?: string
  LAB_TLS_CERT?: string
  LAB_TLS_KEY?: string
  API_TARGET?: string
}

/**
 * TLS de laboratorio (S2-45). Con LAB_TLS=1 el servidor de Vite sirve HTTPS con un certificado de
 * `mkcert`. Por defecto busca `secrets/tls/localhost.pem` y `localhost-key.pem` en la raíz del
 * repositorio (carpeta ignorada por Git); LAB_TLS_CERT y LAB_TLS_KEY permiten otras rutas.
 *
 * Sin LAB_TLS devuelve null y se sigue sirviendo HTTP, como hasta ahora. Si LAB_TLS=1 pero faltan los
 * archivos falla con un mensaje claro: nunca se degrada en silencio a HTTP.
 */
export function loadLabTls(env: LabTlsEnv, repoRoot: string): LabTls | null {
  if (env.LAB_TLS !== '1') return null
  const certPath = resolve(repoRoot, env.LAB_TLS_CERT ?? 'secrets/tls/localhost.pem')
  const keyPath = resolve(repoRoot, env.LAB_TLS_KEY ?? 'secrets/tls/localhost-key.pem')
  const missing = [certPath, keyPath].filter((path) => !existsSync(path))
  if (missing.length > 0) {
    throw new Error(
      `LAB_TLS=1 pero faltan archivos del certificado: ${missing.join(', ')}. ` +
        'Créalos con: mkcert -install && mkcert -cert-file secrets/tls/localhost.pem -key-file secrets/tls/localhost-key.pem localhost 127.0.0.1 ::1',
    )
  }
  return { cert: readFileSync(certPath), key: readFileSync(keyPath) }
}

/** Destino del proxy /api. Con TLS de laboratorio se espera HTTPS, pero se respeta API_TARGET si se define. */
export function apiTarget(env: LabTlsEnv, tlsEnabled: boolean): string {
  const configured = env.API_TARGET?.trim()
  if (configured) return configured.replace(/\/+$/, '')
  return tlsEnabled ? 'https://localhost:3000' : 'http://localhost:3000'
}
