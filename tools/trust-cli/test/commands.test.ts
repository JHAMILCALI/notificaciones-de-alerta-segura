import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { computeKid, verifyManifest, VerificationError } from '@alertasegura/verification';
import { run } from '../src/cli.ts';
import { initRoot, issueManifest, keygenSigner, revoke, rotate } from '../src/commands.ts';
import { CliError } from '../src/errors.ts';
import { assertOutsideRepo, assertPrivateOutputAllowed } from '../src/paths.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../..');
const ISSUER_A = '3f1c9a52-8d3e-4c1b-9f6a-2b7d5e1a0c11';
const ISSUER_B = '9b2e7f10-4a6d-4d58-8c33-5e0f1a7b2d44';
const T0 = new Date('2026-10-26T12:00:00Z');

let tmp: string;
let rootDir: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'trust-cli-'));
  rootDir = join(tmp, 'root');
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

async function expectCliError(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).code).toBe(code);
    return;
  }
  throw new Error(`Se esperaba CliError ${code}`);
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

async function rootJwk() {
  return readJson(join(rootDir, 'root.public.jwk.json'));
}

async function setupWithManifest(version = 1) {
  await initRoot({ rootDir });
  const signer = await keygenSigner({ out: join(tmp, 'secrets', 'signer') });
  const out = join(tmp, 'secrets', 'manifest.json');
  await issueManifest({
    rootDir,
    version,
    hours: 24,
    signerJwkPath: join(signer.out, 'public.jwk.json'),
    issuers: [ISSUER_A],
    out,
    now: T0,
  });
  return { signer, out };
}

describe('init-root', () => {
  it('crea la raíz fuera del repositorio con la privada en PKCS#8 y la pública sin d', async () => {
    const { keyId } = await initRoot({ rootDir });
    const pem = readFileSync(join(rootDir, 'root.private.pem'), 'utf8');
    expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(createPrivateKey(pem).asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    const jwk = (await rootJwk()) as Record<string, unknown>;
    expect(jwk).not.toHaveProperty('d');
    expect(await computeKid(jwk)).toBe(keyId);
    if (process.platform !== 'win32') expect(statSync(join(rootDir, 'root.private.pem')).mode & 0o777).toBe(0o600);
  });

  it('no sobrescribe una raíz existente', async () => {
    await initRoot({ rootDir });
    await expectCliError(initRoot({ rootDir }), 'FILE_EXISTS');
  });

  it('rechaza una raíz dentro del repositorio, incluso en secrets/', async () => {
    await expectCliError(initRoot({ rootDir: join(repoRoot, 'secrets', 'root') }), 'PATH_INSIDE_REPO');
    await expectCliError(initRoot({ rootDir: join(repoRoot, 'apps', 'signer', 'root') }), 'PATH_INSIDE_REPO');
    expect(() => assertOutsideRepo(rootDir, 'x')).not.toThrow();
  });
});

describe('keygen-signer', () => {
  it('guarda la privada PKCS#8 (0400) y la pública JWK, e informa el key_id', async () => {
    const out = join(tmp, 'secrets', 'signer');
    const { keyId } = await keygenSigner({ out });
    const pem = readFileSync(join(out, 'private.pem'), 'utf8');
    expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    const jwk = readJson(join(out, 'public.jwk.json')) as Record<string, unknown>;
    expect(jwk).not.toHaveProperty('d');
    expect(await computeKid(jwk)).toBe(keyId);
    if (process.platform !== 'win32') expect(statSync(join(out, 'private.pem')).mode & 0o777).toBe(0o400);
  });

  it('no pisa una clave existente', async () => {
    const out = join(tmp, 'secrets', 'signer');
    await keygenSigner({ out });
    await expectCliError(keygenSigner({ out }), 'FILE_EXISTS');
  });

  it('dentro del repositorio solo admite carpetas secrets/', async () => {
    expect(() => assertPrivateOutputAllowed(join(repoRoot, 'secrets', 'signer', 'private.pem'), 'x')).not.toThrow();
    expect(() => assertPrivateOutputAllowed(join(repoRoot, 'tools', 'trust-cli', 'secrets', 's', 'private.pem'), 'x')).not.toThrow();
    expect(() => assertPrivateOutputAllowed(join(repoRoot, 'apps', 'signer', 'private.pem'), 'x')).toThrow(CliError);
    expect(() => assertPrivateOutputAllowed(join(repoRoot, 'private.pem'), 'x')).toThrow(CliError);
    // Una carpeta llamada secrets que es el propio archivo no cuenta.
    expect(() => assertPrivateOutputAllowed(join(repoRoot, 'docs', 'secrets'), 'x')).toThrow(CliError);
    expect(() => assertPrivateOutputAllowed(join(tmp, 'cualquiera', 'private.pem'), 'x')).not.toThrow();
  });

  it('rechaza escribir la clave en el repositorio fuera de secrets/ sin crear nada', async () => {
    const out = join(repoRoot, 'packages', 'trust-test-no-crear');
    await expectCliError(keygenSigner({ out }), 'PRIVATE_PATH_IN_REPO');
    expect(() => statSync(out)).toThrow();
  });
});

describe('issue-manifest', () => {
  it('emite un manifiesto que verifica con verifyManifest', async () => {
    const { signer, out } = await setupWithManifest(1);
    const envelope = readJson(out);
    const manifest = await verifyManifest({ envelope, rootJwk: await rootJwk(), ahora: new Date('2026-10-26T13:00:00Z'), versionMinima: 1 });
    expect(manifest.version).toBe(1);
    expect(manifest.key_id_activo).toBe(signer.keyId);
    expect(manifest.claves.map((c) => c.key_id)).toEqual([signer.keyId]);
    expect(manifest.revocadas).toEqual([]);
    expect(manifest.emisores_autorizados).toEqual([ISSUER_A]);
    expect(manifest.issued_at).toBe('2026-10-26T12:00:00Z');
    expect(manifest.expires_at).toBe('2026-10-27T12:00:00Z');
  });

  it('el manifiesto no contiene material privado', async () => {
    const { out } = await setupWithManifest(1);
    const raw = readFileSync(out, 'utf8');
    expect(raw).not.toMatch(/PRIVATE KEY/);
    const payload = Buffer.from((readJson(out) as { payload_canonico: string }).payload_canonico, 'base64url').toString('utf8');
    expect(payload).not.toMatch(/"d"\s*:/);
  });

  it('rechaza una versión menor o igual a la anterior', async () => {
    const { signer, out } = await setupWithManifest(5);
    const base = { rootDir, hours: 24, signerJwkPath: join(signer.out, 'public.jwk.json'), issuers: [ISSUER_A], out, now: T0 };
    await expectCliError(issueManifest({ ...base, version: 5 }), 'VERSION_NOT_INCREASING');
    await expectCliError(issueManifest({ ...base, version: 4 }), 'VERSION_NOT_INCREASING');
    await expect(issueManifest({ ...base, version: 6 })).resolves.toMatchObject({ version: 6 });
  });

  it('rechaza vigencias fuera de 1 h a 7 días y versiones inválidas', async () => {
    await initRoot({ rootDir });
    const signer = await keygenSigner({ out: join(tmp, 'secrets', 'signer') });
    const base = { rootDir, signerJwkPath: join(signer.out, 'public.jwk.json'), issuers: [], out: join(tmp, 'm.json'), now: T0 };
    await expectCliError(issueManifest({ ...base, version: 1, hours: 169 }), 'HOURS_INVALID');
    await expectCliError(issueManifest({ ...base, version: 1, hours: 0 }), 'HOURS_INVALID');
    await expectCliError(issueManifest({ ...base, version: 0, hours: 24 }), 'VERSION_INVALID');
    await expect(issueManifest({ ...base, version: 1, hours: 168 })).resolves.toMatchObject({ version: 1 });
  });

  it('rechaza emisores que no son UUID', async () => {
    await initRoot({ rootDir });
    const signer = await keygenSigner({ out: join(tmp, 'secrets', 'signer') });
    await expectCliError(
      issueManifest({
        rootDir,
        version: 1,
        hours: 24,
        signerJwkPath: join(signer.out, 'public.jwk.json'),
        issuers: ['no-es-uuid'],
        out: join(tmp, 'm.json'),
        now: T0,
      }),
      'MANIFEST_INVALID',
    );
  });

  it('rechaza una JWK del firmante que contiene la clave privada', async () => {
    await initRoot({ rootDir });
    const signer = await keygenSigner({ out: join(tmp, 'secrets', 'signer') });
    const jwkPath = join(signer.out, 'public.jwk.json');
    const withD = join(tmp, 'con-d.jwk.json');
    mkdirSync(dirname(withD), { recursive: true });
    const { writeFileSync } = await import('node:fs');
    writeFileSync(withD, JSON.stringify({ ...(readJson(jwkPath) as object), d: 'AAAA' }));
    await expectCliError(
      issueManifest({ rootDir, version: 1, hours: 24, signerJwkPath: withD, issuers: [], out: join(tmp, 'm.json'), now: T0 }),
      'JWK_INVALID',
    );
  });

  it('sin raíz creada falla con un error claro', async () => {
    await expectCliError(
      issueManifest({ rootDir, version: 1, hours: 24, signerJwkPath: join(tmp, 'x'), issuers: [], out: join(tmp, 'm.json'), now: T0 }),
      'KEY_NOT_FOUND',
    );
  });
});

describe('rotate y revoke', () => {
  it('rotate activa una clave nueva y deja la anterior retirada, no revocada', async () => {
    const { signer, out } = await setupWithManifest(1);
    const result = await rotate({ rootDir, version: 2, signerOut: join(tmp, 'secrets', 'signer-v2'), out, now: new Date('2026-10-26T18:00:00Z') });
    const manifest = await verifyManifest({
      envelope: readJson(out),
      rootJwk: await rootJwk(),
      ahora: new Date('2026-10-26T19:00:00Z'),
      versionMinima: 2,
    });
    expect(manifest.key_id_activo).toBe(result.signerKeyId);
    expect(manifest.claves.map((c) => c.key_id).sort()).toEqual([signer.keyId, result.signerKeyId].sort());
    expect(manifest.revocadas).toEqual([]);
    expect(manifest.expires_at).toBe('2026-10-27T18:00:00Z');
  });

  it('rotate --revoke-previous revoca la anterior', async () => {
    const { signer, out } = await setupWithManifest(1);
    const result = await rotate({
      rootDir,
      version: 2,
      signerOut: join(tmp, 'secrets', 'signer-v2'),
      out,
      revokePrevious: true,
      now: T0,
    });
    const manifest = await verifyManifest({ envelope: readJson(out), rootJwk: await rootJwk(), ahora: T0, versionMinima: 2 });
    expect(manifest.revocadas).toEqual([signer.keyId]);
    expect(manifest.key_id_activo).toBe(result.signerKeyId);
  });

  it('rotate con versión no creciente no genera ninguna clave', async () => {
    const { out } = await setupWithManifest(3);
    const signerOut = join(tmp, 'secrets', 'signer-huerfana');
    await expectCliError(rotate({ rootDir, version: 3, signerOut, out, now: T0 }), 'VERSION_NOT_INCREASING');
    expect(() => statSync(signerOut)).toThrow();
  });

  it('revoke revoca una clave retirada y emite la versión siguiente', async () => {
    const { signer, out } = await setupWithManifest(1);
    await rotate({ rootDir, version: 2, signerOut: join(tmp, 'secrets', 'signer-v2'), out, now: T0 });
    const summary = await revoke({ rootDir, keyId: signer.keyId, version: 3, out, now: T0 });
    expect(summary.revocadas).toEqual([signer.keyId]);
    const manifest = await verifyManifest({ envelope: readJson(out), rootJwk: await rootJwk(), ahora: T0, versionMinima: 3 });
    expect(manifest.version).toBe(3);
    expect(manifest.revocadas).toEqual([signer.keyId]);
  });

  it('revoke rechaza la clave activa, una desconocida, una ya revocada y una versión no creciente', async () => {
    const { signer, out } = await setupWithManifest(1);
    await expectCliError(revoke({ rootDir, keyId: signer.keyId, version: 2, out, now: T0 }), 'ACTIVE_KEY');
    await expectCliError(revoke({ rootDir, keyId: 'A'.repeat(43), version: 2, out, now: T0 }), 'KEY_UNKNOWN');
    await rotate({ rootDir, version: 2, signerOut: join(tmp, 'secrets', 'signer-v2'), out, now: T0 });
    await revoke({ rootDir, keyId: signer.keyId, version: 3, out, now: T0 });
    await expectCliError(revoke({ rootDir, keyId: signer.keyId, version: 4, out, now: T0 }), 'KEY_ALREADY_REVOKED');
    await expectCliError(revoke({ rootDir, keyId: signer.keyId, version: 3, out, now: T0 }), 'VERSION_NOT_INCREASING');
  });

  it('una clave revocada no vuelve a ser la activa con issue-manifest', async () => {
    const { signer, out } = await setupWithManifest(1);
    await rotate({ rootDir, version: 2, signerOut: join(tmp, 'secrets', 'signer-v2'), out, revokePrevious: true, now: T0 });
    await expectCliError(
      issueManifest({
        rootDir,
        version: 3,
        hours: 24,
        signerJwkPath: join(signer.out, 'public.jwk.json'),
        issuers: [],
        out,
        now: T0,
      }),
      'KEY_REVOKED',
    );
  });

  it('verifyManifest rechaza el manifiesto emitido si se exige una versión mayor', async () => {
    const { out } = await setupWithManifest(2);
    await expect(
      verifyManifest({ envelope: readJson(out), rootJwk: await rootJwk(), ahora: T0, versionMinima: 3 }),
    ).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('línea de comandos', () => {
  it('recorre init-root, keygen-signer e issue-manifest e imprime los key_id', async () => {
    const lines: string[] = [];
    const io = { out: (line: string) => lines.push(line) };
    const signerDir = join(tmp, 'secrets', 'signer');
    const manifestPath = join(tmp, 'secrets', 'manifest.json');
    await run(['init-root', '--root-dir', rootDir], io);
    await run(['keygen-signer', '--out', signerDir], io);
    await run(
      [
        'issue-manifest',
        '--root-dir', rootDir,
        '--version', '1',
        '--hours', '24',
        '--signer-jwk', join(signerDir, 'public.jwk.json'),
        '--issuers', `${ISSUER_A},${ISSUER_B}`,
        '--out', manifestPath,
      ],
      io,
    );
    expect(lines.some((l) => l.startsWith('root_key_id: '))).toBe(true);
    expect(lines.some((l) => /^key_id: [A-Za-z0-9_-]{43}$/.test(l))).toBe(true);
    const manifest = await verifyManifest({
      envelope: readJson(manifestPath),
      rootJwk: await rootJwk(),
      ahora: new Date(),
      versionMinima: 1,
    });
    expect(manifest.emisores_autorizados).toEqual([ISSUER_A, ISSUER_B]);
  });

  it('rechaza comandos y opciones desconocidos', async () => {
    const io = { out: () => {} };
    await expectCliError(run(['borrar-todo'], io), 'UNKNOWN_COMMAND');
    await expect(run(['init-root', '--no-existe'], io)).rejects.toThrow();
    await expectCliError(run(['issue-manifest', '--root-dir', rootDir], io), 'MISSING_OPTION');
    await expectCliError(run(['issue-manifest', '--version', 'x'], io), 'INVALID_OPTION');
  });
});
