import { randomBytes } from 'node:crypto';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import type TestAgent from 'supertest/lib/agent';
import {
  createPrismaClient,
  hashPassword,
  type PrismaClient,
  type Role,
} from '@alertasegura/database';
import {
  CSRF_HEADER,
  type CsrfResponse,
  type LoginResponse,
} from '@alertasegura/shared';
import { AppModule } from '../../src/app.module';
import { CLOCK, type Clock } from '../../src/common/clock/clock';
import { SIGNER_CLIENT } from '../../src/modules/signer/signer.client';
import { FakeSigner } from './fake-signer';
import { configureApp } from '../../src/app.setup';
import { APP_CONFIG } from '../../src/config/config.module';
import type { AppConfig } from '../../src/config/env';
import { PrismaService } from '../../src/database/prisma.service';

export const API = '/api/v1';
export const WEB_ORIGIN = 'http://localhost:5173';

export interface ConfigOverrides {
  cookieSecure?: boolean;
  trustProxy?: false | number;
  session?: Partial<AppConfig['session']>;
  rateLimits?: Partial<AppConfig['rateLimits']>;
  /** Ruta del manifiesto de confianza firmado (por defecto, no configurado → 503). */
  trustManifestFile?: string | null;
  /** Firmante de la API; por defecto, un firmante falso de prueba con clave efímera. */
  signer?: FakeSigner;
  /** Reloj de la API; por defecto, un reloj controlable que parte de la hora real. */
  clock?: TestClock;
}

/** Reloj controlable: las pruebas lo adelantan para vencer alertas y estados sin esperar. */
export class TestClock implements Clock {
  private current: number;
  constructor(start: Date = new Date()) {
    this.current = start.getTime();
  }
  now(): Date {
    return new Date(this.current);
  }
  advance(ms: number): void {
    this.current += ms;
  }
  set(date: Date): void {
    this.current = date.getTime();
  }
}

export function testConfig(overrides: ConfigOverrides = {}): AppConfig {
  const databaseUrl = process.env.TEST_DATABASE_URL;
  if (!databaseUrl)
    throw new Error(
      'TEST_DATABASE_URL no definida (globalSetup no se ejecutó)',
    );
  // Por defecto los límites son altísimos para no interferir; P09 inyecta límites bajos.
  const generous = { limit: 100_000, windowSeconds: 60 };
  return {
    nodeEnv: 'test',
    port: 0,
    databaseUrl,
    webOrigin: WEB_ORIGIN,
    csrfSecret: randomBytes(32).toString('hex'),
    cookieSecure: overrides.cookieSecure ?? false,
    trustProxy: overrides.trustProxy ?? false,
    bodyLimit: '100kb',
    session: {
      absoluteTtlMs: 8 * 3600_000,
      idleTtlMs: 30 * 60_000,
      ...overrides.session,
    },
    rateLimits: {
      loginIp: generous,
      loginAccount: generous,
      user: generous,
      global: generous,
      publish: generous,
      ...overrides.rateLimits,
    },
    signer: { socketPath: '/nonexistent/signer.sock', timeoutMs: 3000 },
    trustManifestFile: overrides.trustManifestFile ?? null,
  };
}

export interface TestApp {
  app: NestExpressApplication;
  /** Cliente de la app: conectado con el rol alertasegura_app, igual que la API. */
  prisma: PrismaClient;
  /** Cliente con el rol propietario de la base de prueba (preparar datos y comprobar triggers). */
  owner: PrismaClient;
  config: AppConfig;
  /** Firmante falso conectado a la API de la prueba. */
  signer: FakeSigner;
  /** Reloj que usa la API para fechar documentos. */
  clock: TestClock;
  /** Cliente HTTP con jar de cookies propio (un navegador). */
  browser: () => TestAgent;
  close: () => Promise<void>;
}

/** Levanta la aplicación real (AppModule + configureApp) contra PostgreSQL. */
export async function createTestApp(
  overrides: ConfigOverrides = {},
): Promise<TestApp> {
  const config = testConfig(overrides);
  const signer = overrides.signer ?? new FakeSigner();
  const clock = overrides.clock ?? new TestClock();
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(APP_CONFIG)
    .useValue(config)
    .overrideProvider(SIGNER_CLIENT)
    .useValue(signer)
    .overrideProvider(CLOCK)
    .useValue(clock)
    .compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>({
    logger: ['error'],
  });
  await configureApp(app);
  const prisma = app.get(PrismaService);
  const ownerUrl = process.env.TEST_OWNER_DATABASE_URL;
  if (!ownerUrl)
    throw new Error(
      'TEST_OWNER_DATABASE_URL no definida (globalSetup no se ejecutó)',
    );
  const owner = createPrismaClient({
    connectionString: ownerUrl,
    maxConnections: 2,
  });
  return {
    app,
    prisma,
    owner,
    config,
    signer,
    clock,
    browser: () => request.agent(app.getHttpServer()),
    close: async () => {
      await owner.$disconnect();
      await app.close();
    },
  };
}

export interface TestUser {
  id: string;
  email: string;
  password: string;
  role: Role;
  displayName: string;
}

let counter = 0;
/** Usuario nuevo con correo único y contraseña aleatoria generada en la propia prueba. */
export async function createUser(
  prisma: PrismaClient,
  role: Role,
  extra: { status?: 'ACTIVE' | 'DISABLED' } = {},
): Promise<TestUser> {
  counter += 1;
  const email = `${role.toLowerCase()}-${counter}-${randomBytes(4).toString('hex')}@test.local`;
  const password = `Pw-${randomBytes(12).toString('base64url')}`;
  const displayName = `Usuario ${role} ${counter}`;
  const user = await prisma.user.create({
    data: {
      email,
      displayName,
      passwordHash: await hashPassword(password),
      role,
      status: extra.status ?? 'ACTIVE',
    },
  });
  return { id: user.id, email, password, role, displayName };
}

export async function fetchCsrf(agent: TestAgent): Promise<string> {
  const res = await agent.get(`${API}/auth/csrf`).expect(200);
  return (res.body as CsrfResponse).csrfToken;
}

/** Login completo como lo haría la PWA: pide CSRF, envía credenciales y recibe el token nuevo. */
export async function login(
  agent: TestAgent,
  user: Pick<TestUser, 'email' | 'password'>,
): Promise<{ csrfToken: string; body: LoginResponse; setCookie: string[] }> {
  const pre = await fetchCsrf(agent);
  const res = await agent
    .post(`${API}/auth/login`)
    .set(CSRF_HEADER, pre)
    .send({ email: user.email, password: user.password })
    .expect(200);
  const body = res.body as LoginResponse;
  return {
    csrfToken: body.csrfToken,
    body,
    setCookie: res.headers['set-cookie'] as unknown as string[],
  };
}

/** Navegador ya autenticado. */
export async function loggedInBrowser(
  testApp: TestApp,
  user: TestUser,
): Promise<{ agent: TestAgent; csrfToken: string }> {
  const agent = testApp.browser();
  const { csrfToken } = await login(agent, user);
  return { agent, csrfToken };
}

export function auditRows(
  prisma: PrismaClient,
  where: Record<string, unknown>,
) {
  return prisma.auditLog.findMany({ where, orderBy: { occurredAt: 'asc' } });
}

/** Cuerpo válido de POST /drafts (D-4: campos oficiales de Bolivia). */
export const validDraftBody = {
  tipo: 'LLUVIAS_INTENSAS',
  zona: { departamento: 'LA_PAZ', municipio: 'Palca' },
  severidad: 'ROJA',
  mensaje: 'Lluvias intensas en la cuenca; evite cruzar quebradas y ríos.',
  vigenciaHoras: 12,
} as const;

/** Inserta un borrador directamente en la base (sin pasar por la API). */
export function createDraftRow(
  prisma: PrismaClient,
  ownerId: string,
  overrides: Partial<{
    mensaje: string;
    severidad: 'AMARILLA' | 'NARANJA' | 'ROJA';
  }> = {},
) {
  return prisma.draft.create({
    data: {
      tipo: 'LLUVIAS_INTENSAS',
      departamento: 'LA_PAZ',
      municipio: null,
      severidad: overrides.severidad ?? 'NARANJA',
      mensaje: overrides.mensaje ?? 'Borrador de prueba con texto suficiente.',
      vigenciaHoras: 24,
      ownerId,
    },
  });
}
