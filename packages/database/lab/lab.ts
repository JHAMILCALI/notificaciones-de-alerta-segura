import path from 'node:path';
import { parseArgs } from 'node:util';
import { config } from 'dotenv';
import { addIssuer, AddIssuerError, createPrismaClient } from '../src/index';

// El cwd de pnpm es packages/database; el .env está en la raíz del monorepo.
config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

const USAGE = `Comandos de laboratorio (solo desarrollo local; usan el rol propietario de la base).

  pnpm --filter @alertasegura/database lab issuer:add --email <correo> --name <nombre>

La contraseña nunca va por argumento: se toma de LAB_ISSUER_PASSWORD, de la entrada estándar
(echo "..." | pnpm ...) o, en una terminal interactiva, se pide sin mostrarla.
`;

function fail(message: string): never {
  console.error(`[lab] ${message}`);
  process.exit(1);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk as Uint8Array));
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

/** Pide la contraseña en una terminal sin imprimirla. */
function promptHidden(question: string): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    let value = '';
    process.stderr.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (key: string): void => {
      for (const char of key) {
        if (char === '\u0003') {
          stdin.setRawMode(false);
          process.stderr.write('\n');
          process.exit(130);
        } else if (char === '\r' || char === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          process.stderr.write('\n');
          resolve(value);
          return;
        } else if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1);
        } else {
          value += char;
        }
      }
    };
    stdin.on('data', onData);
  });
}

async function readPassword(): Promise<string> {
  const fromEnv = process.env.LAB_ISSUER_PASSWORD;
  if (fromEnv) return fromEnv;
  if (process.stdin.isTTY) return promptHidden('Contraseña del emisor: ');
  return readStdin();
}

async function issuerAdd(argv: string[]): Promise<void> {
  let values: { email?: string; name?: string };
  try {
    ({ values } = parseArgs({
      args: argv,
      options: { email: { type: 'string' }, name: { type: 'string' } },
      strict: true,
    }));
  } catch (error) {
    const hint = argv.some((a) => a.startsWith('--password'))
      ? ' La contraseña no se acepta por argumento (queda en el historial de la terminal).'
      : '';
    fail(`${error instanceof Error ? error.message : 'argumentos inválidos'}.${hint}\n\n${USAGE}`);
  }
  if (!values.email || !values.name) fail(`Faltan --email y --name.\n\n${USAGE}`);

  const url = process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL;
  if (!url) fail('Falta DATABASE_MIGRATION_URL o DATABASE_URL (revise el .env de la raíz).');

  const password = await readPassword();
  const prisma = createPrismaClient({ connectionString: url, maxConnections: 2 });
  try {
    const issuer = await addIssuer(prisma, { email: values.email, displayName: values.name, password });
    console.log(`[lab] emisor creado: ${issuer.email} (id ${issuer.id}). Auditado como ISSUER_PROVISIONED.`);
  } catch (error) {
    if (error instanceof AddIssuerError) fail(error.message);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case 'issuer:add':
      return issuerAdd(rest);
    default:
      fail(`Comando desconocido: ${command ?? '(ninguno)'}.\n\n${USAGE}`);
  }
}

main().catch((error: unknown) => {
  console.error('[lab] fallo:', error instanceof Error ? error.message : error);
  process.exit(1);
});
