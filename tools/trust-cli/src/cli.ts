import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { initRoot, issueManifest, keygenSigner, revoke, rotate, type ManifestSummary } from './commands.ts';
import { CliError } from './errors.ts';
import { defaultRootDir } from './paths.ts';

export const USAGE = `alertasegura-trust: CLI de confianza de laboratorio (la raíz vive FUERA del repositorio)

Comandos:
  init-root         [--root-dir DIR]
  keygen-signer     --out secrets/signer
  issue-manifest    --version N --hours H --signer-jwk ARCHIVO --issuers UUID,UUID --out secrets/manifest.json [--root-dir DIR]
  revoke            --key-id ID --version N+1 [--hours H] [--out secrets/manifest.json] [--root-dir DIR]
  rotate            --version N+1 [--signer-out secrets/signer-vN] [--out secrets/manifest.json] [--hours H] [--revoke-previous] [--root-dir DIR]

--root-dir por defecto: ${defaultRootDir()}
`;

export interface Io {
  out: (line: string) => void;
}

function toInt(name: string, value: string | undefined): number {
  if (value === undefined) throw new CliError('MISSING_OPTION', `Falta --${name}`);
  if (!/^\d+$/.test(value)) throw new CliError('INVALID_OPTION', `--${name} debe ser un entero positivo`);
  return Number(value);
}

function required(name: string, value: string | undefined): string {
  if (value === undefined || value === '') throw new CliError('MISSING_OPTION', `Falta --${name}`);
  return value;
}

function printManifest(io: Io, title: string, summary: ManifestSummary): void {
  io.out(`${title}: versión ${summary.version}`);
  io.out(`issued_at: ${summary.issuedAt}`);
  io.out(`expires_at: ${summary.expiresAt}`);
  io.out(`key_id_activo: ${summary.keyIdActivo}`);
  io.out(`revocadas: ${summary.revocadas.length}`);
  io.out(`manifiesto: ${summary.out}`);
}

export async function run(argv: string[], io: Io): Promise<void> {
  const [command, ...rest] = argv;
  if (command === undefined || command === '--help' || command === '-h') {
    io.out(USAGE);
    return;
  }
  const { values } = parseArgs({
    args: rest,
    strict: true,
    allowPositionals: false,
    options: {
      'root-dir': { type: 'string' },
      out: { type: 'string' },
      'signer-out': { type: 'string' },
      'signer-jwk': { type: 'string' },
      issuers: { type: 'string' },
      'key-id': { type: 'string' },
      version: { type: 'string' },
      hours: { type: 'string' },
      'revoke-previous': { type: 'boolean' },
    },
  });
  const rootDir = values['root-dir'] ?? defaultRootDir();
  const manifestOut = values.out ?? join('secrets', 'manifest.json');

  switch (command) {
    case 'init-root': {
      const result = await initRoot({ rootDir });
      io.out(`Raíz creada en ${result.rootDir}`);
      io.out(`root_key_id: ${result.keyId}`);
      return;
    }
    case 'keygen-signer': {
      const result = await keygenSigner({ out: required('out', values.out) });
      io.out(`Clave del firmante creada en ${result.out}`);
      io.out(`key_id: ${result.keyId}`);
      return;
    }
    case 'issue-manifest': {
      const issuers = (values.issuers ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s !== '');
      const summary = await issueManifest({
        rootDir,
        version: toInt('version', values.version),
        hours: toInt('hours', values.hours),
        signerJwkPath: required('signer-jwk', values['signer-jwk']),
        issuers,
        out: required('out', values.out),
      });
      printManifest(io, 'Manifiesto emitido', summary);
      return;
    }
    case 'revoke': {
      const summary = await revoke({
        rootDir,
        keyId: required('key-id', values['key-id']),
        version: toInt('version', values.version),
        hours: values.hours === undefined ? undefined : toInt('hours', values.hours),
        out: manifestOut,
      });
      printManifest(io, 'Clave revocada, manifiesto emitido', summary);
      return;
    }
    case 'rotate': {
      const version = toInt('version', values.version);
      const summary = await rotate({
        rootDir,
        version,
        signerOut: values['signer-out'] ?? join('secrets', `signer-v${version}`),
        hours: values.hours === undefined ? undefined : toInt('hours', values.hours),
        revokePrevious: values['revoke-previous'] === true,
        out: manifestOut,
      });
      io.out(`Clave nueva del firmante: ${summary.signerKeyId}`);
      printManifest(io, 'Rotación completada, manifiesto emitido', summary);
      return;
    }
    default:
      throw new CliError('UNKNOWN_COMMAND', `Comando desconocido: ${command}\n\n${USAGE}`);
  }
}
