import { ConfigError, loadConfig } from './env';

const valid = {
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  WEB_ORIGIN: 'http://localhost:5173',
  CSRF_SECRET: 'x'.repeat(32),
};

describe('loadConfig (validación con Zod, falla rápido)', () => {
  it('aplica los valores por defecto del contrato', () => {
    const config = loadConfig({ ...valid });
    expect(config.port).toBe(3000);
    expect(config.cookieSecure).toBe(false);
    expect(config.trustProxy).toBe(false);
    expect(config.session).toEqual({
      absoluteTtlMs: 8 * 3600_000,
      idleTtlMs: 30 * 60_000,
    });
    expect(config.rateLimits.loginIp).toEqual({ limit: 10, windowSeconds: 60 });
    expect(config.rateLimits.loginAccount).toEqual({
      limit: 5,
      windowSeconds: 900,
    });
    expect(config.rateLimits.user).toEqual({ limit: 120, windowSeconds: 60 });
    expect(config.rateLimits.global).toEqual({ limit: 300, windowSeconds: 60 });
  });

  it('configura el firmante y el manifiesto de confianza', () => {
    const defaults = loadConfig({ ...valid });
    expect(defaults.signer).toEqual({
      socketPath: '/run/signer/signer.sock',
      timeoutMs: 3000,
    });
    expect(defaults.trustManifestFile).toBeNull();
    const pipe = String.raw`\\.\pipe\alertasegura-signer`; // named pipe de Windows
    const custom = loadConfig({
      ...valid,
      SIGNER_SOCKET_PATH: pipe,
      SIGNER_TIMEOUT_MS: '1500',
      TRUST_MANIFEST_FILE: '  ./secrets/manifest.json ',
    });
    expect(custom.signer).toEqual({
      socketPath: pipe,
      timeoutMs: 1500,
    });
    expect(custom.trustManifestFile).toBe('./secrets/manifest.json');
    expect(() => loadConfig({ ...valid, SIGNER_TIMEOUT_MS: '0' })).toThrow(
      ConfigError,
    );
    expect(
      loadConfig({ ...valid, TRUST_MANIFEST_FILE: '' }).trustManifestFile,
    ).toBeNull();
  });

  it('exige CSRF_SECRET de al menos 32 bytes', () => {
    expect(() => loadConfig({ ...valid, CSRF_SECRET: 'x'.repeat(31) })).toThrow(
      ConfigError,
    );
    expect(() => loadConfig({ ...valid, CSRF_SECRET: '' })).toThrow(
      ConfigError,
    );
    const without: NodeJS.ProcessEnv = { ...valid };
    delete without.CSRF_SECRET;
    expect(() => loadConfig(without)).toThrow(/CSRF_SECRET/);
  });

  it('rechaza el placeholder de .env.example y cualquier valor "replace-with…"', () => {
    const placeholder = 'replace-with-at-least-32-random-bytes-hex';
    expect(placeholder.length).toBeGreaterThan(32); // mide más de 32: antes se aceptaba
    expect(() => loadConfig({ ...valid, CSRF_SECRET: placeholder })).toThrow(
      /CSRF_SECRET/,
    );
    for (const value of [
      'replace-with-' + 'x'.repeat(40),
      'REPLACE-WITH-' + 'x'.repeat(40),
      '  replace-with-' + 'x'.repeat(40),
    ]) {
      expect(() => loadConfig({ ...valid, CSRF_SECRET: value })).toThrow(
        ConfigError,
      );
    }
    // un secreto aleatorio legítimo sigue valiendo
    expect(
      loadConfig({ ...valid, CSRF_SECRET: 'a1b2c3d4'.repeat(8) }).csrfSecret,
    ).toHaveLength(64);
  });

  it('exige DATABASE_URL y WEB_ORIGIN válidos', () => {
    expect(() => loadConfig({ ...valid, DATABASE_URL: 'mysql://x' })).toThrow(
      /DATABASE_URL/,
    );
    expect(() => loadConfig({ ...valid, WEB_ORIGIN: 'no-es-url' })).toThrow(
      /WEB_ORIGIN/,
    );
  });

  it('normaliza WEB_ORIGIN a origen (sin ruta ni barra final)', () => {
    expect(
      loadConfig({ ...valid, WEB_ORIGIN: 'http://localhost:5173/' }).webOrigin,
    ).toBe('http://localhost:5173');
  });

  it('interpreta COOKIE_SECURE y TRUST_PROXY de forma estricta', () => {
    expect(loadConfig({ ...valid, COOKIE_SECURE: 'true' }).cookieSecure).toBe(
      true,
    );
    expect(() => loadConfig({ ...valid, COOKIE_SECURE: 'yes' })).toThrow(
      /COOKIE_SECURE/,
    );
    expect(loadConfig({ ...valid, TRUST_PROXY: '2' }).trustProxy).toBe(2);
    expect(loadConfig({ ...valid, TRUST_PROXY: 'true' }).trustProxy).toBe(1);
    expect(() => loadConfig({ ...valid, TRUST_PROXY: 'maybe' })).toThrow(
      /TRUST_PROXY/,
    );
  });

  it('rechaza límites no numéricos o no positivos', () => {
    expect(() => loadConfig({ ...valid, RATE_LOGIN_IP_LIMIT: '0' })).toThrow(
      /RATE_LOGIN_IP_LIMIT/,
    );
    expect(() =>
      loadConfig({ ...valid, SESSION_IDLE_TTL_MINUTES: 'abc' }),
    ).toThrow(ConfigError);
  });

  it('el mensaje de error nunca incluye los valores (pueden ser secretos)', () => {
    try {
      loadConfig({ ...valid, CSRF_SECRET: 'secreto-corto' });
      throw new Error('debía fallar');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as Error).message).not.toContain('secreto-corto');
    }
  });
});
