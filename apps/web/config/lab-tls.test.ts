import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { apiTarget, loadLabTls } from './lab-tls.ts'

let root: string
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'lab-tls-'))
})
afterEach(() => {
  rmSync(root, { recursive: true, force: true })
})

function writeCert(dir = 'secrets/tls', cert = 'localhost.pem', key = 'localhost-key.pem') {
  mkdirSync(join(root, dir), { recursive: true })
  writeFileSync(join(root, dir, cert), 'CERT')
  writeFileSync(join(root, dir, key), 'KEY')
}

describe('loadLabTls', () => {
  it('sin LAB_TLS=1 no activa TLS aunque existan los archivos', () => {
    writeCert()
    expect(loadLabTls({}, root)).toBeNull()
    expect(loadLabTls({ LAB_TLS: '0' }, root)).toBeNull()
  })

  it('con LAB_TLS=1 lee secrets/tls/localhost.pem y localhost-key.pem', () => {
    writeCert()
    const tls = loadLabTls({ LAB_TLS: '1' }, root)
    expect(tls?.cert.toString()).toBe('CERT')
    expect(tls?.key.toString()).toBe('KEY')
  })

  it('permite rutas propias con LAB_TLS_CERT y LAB_TLS_KEY', () => {
    writeCert('otra', 'a.pem', 'b.pem')
    const tls = loadLabTls({ LAB_TLS: '1', LAB_TLS_CERT: 'otra/a.pem', LAB_TLS_KEY: 'otra/b.pem' }, root)
    expect(tls?.cert.toString()).toBe('CERT')
  })

  it('con LAB_TLS=1 y sin archivos falla con instrucciones de mkcert, sin degradar a HTTP', () => {
    expect(() => loadLabTls({ LAB_TLS: '1' }, root)).toThrow(/mkcert/)
    expect(() => loadLabTls({ LAB_TLS: '1' }, root)).toThrow(/localhost-key\.pem/)
  })
})

describe('apiTarget', () => {
  it('HTTP por defecto y HTTPS con TLS de laboratorio', () => {
    expect(apiTarget({}, false)).toBe('http://localhost:3000')
    expect(apiTarget({}, true)).toBe('https://localhost:3000')
  })

  it('respeta API_TARGET (por ejemplo la API de otro puerto) sin la barra final', () => {
    expect(apiTarget({ API_TARGET: 'http://localhost:3200/' }, false)).toBe('http://localhost:3200')
    expect(apiTarget({ API_TARGET: 'https://localhost:3200' }, true)).toBe('https://localhost:3200')
  })
})
