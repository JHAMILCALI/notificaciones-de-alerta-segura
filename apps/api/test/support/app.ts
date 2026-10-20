import { randomBytes } from 'node:crypto';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import type TestAgent from 'supertest/lib/agent';
import {
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
      ...overrides.rateLimits,
    },
  };
}

export interface TestApp {
  app: NestExpressApplication;
  prisma: PrismaClient;
  config: AppConfig;
  /** Cliente HTTP con jar de cookies propio (un navegador). */
  browser: () => TestAgent;
  close: () => Promise<void>;
}

/** Levanta la aplicación real (AppModule + configureApp) contra PostgreSQL. */
export async function createTestApp(
  overrides: ConfigOverrides = {},
): Promise<TestApp> {
  const config = testConfig(overrides);
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(APP_CONFIG)
    .useValue(config)
    .compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>({
    logger: ['error'],
  });
  await configureApp(app);
  const prisma = app.get(PrismaService);
  return {
    app,
    prisma,
    config,
    browser: () => request.agent(app.getHttpServer()),
    close: () => app.close(),
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
