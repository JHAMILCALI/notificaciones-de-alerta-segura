import path from 'node:path';
import { config } from 'dotenv';
import {
  createPrismaClient,
  hashPassword,
  Departamento,
  NivelAlerta,
  Role,
  TipoAlerta,
  type PrismaClient,
} from '../src/index';

// El cwd de pnpm es packages/database; el .env está en la raíz del monorepo.
config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

interface SeedUser {
  label: string;
  role: Role;
  emailVar: string;
  passwordVar: string;
  displayName: string;
  required: boolean;
}

const MIN_PASSWORD = 12;

const SEED_USERS: SeedUser[] = [
  {
    label: 'ADMIN',
    role: Role.ADMIN,
    emailVar: 'SEED_ADMIN_EMAIL',
    passwordVar: 'SEED_ADMIN_PASSWORD',
    displayName: process.env.SEED_ADMIN_NAME?.trim() || 'Administrador inicial',
    required: true,
  },
  {
    label: 'AUDITOR',
    role: Role.AUDITOR,
    emailVar: 'SEED_AUDITOR_EMAIL',
    passwordVar: 'SEED_AUDITOR_PASSWORD',
    displayName: 'Auditor de ejemplo',
    required: false,
  },
  {
    label: 'ISSUER 1',
    role: Role.ISSUER,
    emailVar: 'SEED_ISSUER1_EMAIL',
    passwordVar: 'SEED_ISSUER1_PASSWORD',
    displayName: 'Emisor de ejemplo 1',
    required: false,
  },
  {
    label: 'ISSUER 2',
    role: Role.ISSUER,
    emailVar: 'SEED_ISSUER2_EMAIL',
    passwordVar: 'SEED_ISSUER2_PASSWORD',
    displayName: 'Emisor de ejemplo 2',
    required: false,
  },
];

const FICTIONAL_DRAFTS = [
  {
    tipo: TipoAlerta.LLUVIAS_INTENSAS,
    departamento: Departamento.LA_PAZ,
    municipio: 'La Paz',
    severidad: NivelAlerta.NARANJA,
    mensaje:
      'Simulacro: borrador ficticio de demostracion. Se esperan lluvias intensas durante la tarde; evite cruzar quebradas.',
    vigenciaHoras: 12,
  },
  {
    tipo: TipoAlerta.HELADA,
    departamento: Departamento.POTOSI,
    municipio: null,
    severidad: NivelAlerta.AMARILLA,
    mensaje:
      'Simulacro: borrador ficticio de demostracion. Heladas por la madrugada en el altiplano; proteja cultivos y animales.',
    vigenciaHoras: 24,
  },
];

async function seedUser(
  prisma: PrismaClient,
  spec: SeedUser,
  createdById: string | null,
): Promise<string | null> {
  const emailRaw = process.env[spec.emailVar]?.trim();
  const password = process.env[spec.passwordVar];
  if (!emailRaw || !password) {
    console.log(
      `[seed] ${spec.label}: omitido (falta ${spec.emailVar} o ${spec.passwordVar}).` +
        (spec.required ? ' ATENCION: no habra administrador inicial.' : ''),
    );
    return null;
  }
  if (password.length < MIN_PASSWORD) {
    console.log(`[seed] ${spec.label}: omitido (${spec.passwordVar} tiene menos de ${MIN_PASSWORD} caracteres).`);
    return null;
  }
  const email = emailRaw.toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    console.log(`[seed] ${spec.label}: ya existe (${email}); no se modifica.`);
    return existing.id;
  }
  const user = await prisma.user.create({
    data: {
      email,
      displayName: spec.displayName,
      passwordHash: await hashPassword(password),
      role: spec.role,
      createdById,
    },
  });
  console.log(`[seed] ${spec.label}: creado (${email}).`);
  return user.id;
}

async function seed(): Promise<void> {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error('DATABASE_URL no esta definida (revise el .env de la raiz).');
  }
  const prisma = createPrismaClient({ connectionString: url, maxConnections: 2 });
  try {
    const ids: Array<string | null> = [];
    let adminId: string | null = null;
    for (const spec of SEED_USERS) {
      const id = await seedUser(prisma, spec, spec.role === Role.ADMIN ? null : adminId);
      if (spec.role === Role.ADMIN) adminId = id;
      ids.push(id);
    }
    const issuerIds = SEED_USERS.flatMap((s, i) => (s.role === Role.ISSUER && ids[i] ? [ids[i] as string] : []));
    for (const [i, ownerId] of issuerIds.entries()) {
      const draft = FICTIONAL_DRAFTS[i % FICTIONAL_DRAFTS.length];
      if (!draft) continue;
      const exists = await prisma.draft.findFirst({ where: { ownerId, mensaje: draft.mensaje } });
      if (!exists) {
        await prisma.draft.create({ data: { ...draft, ownerId } });
        console.log(`[seed] borrador ficticio creado: ${draft.tipo} en ${draft.departamento}`);
      }
    }
  } finally {
    await prisma.$disconnect();
  }
}

seed().catch((error: unknown) => {
  console.error('[seed] fallo:', error instanceof Error ? error.message : error);
  process.exit(1);
});
