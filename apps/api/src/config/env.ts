import { existsSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

const booleanString = z
  .enum(['true', 'false'])
  .transform((value) => value === 'true');

const positiveInt = z.coerce.number().int().positive();

/** `false` (por defecto) o un número de saltos de proxy de confianza (`true` equivale a 1). */
const trustProxy = z
  .string()
  .trim()
  .transform((value, ctx): false | number => {
    if (value === 'false' || value === '') return false;
    if (value === 'true') return 1;
    const hops = Number(value);
    if (Number.isInteger(hops) && hops > 0 && hops <= 10) return hops;
    ctx.addIssue({
      code: 'custom',
      message: 'debe ser false, true o un entero entre 1 y 10',
    });
    return z.NEVER;
  });

const EnvSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z
    .string()
    .min(1)
    .refine(
      (value) => /^postgres(ql)?:\/\//.test(value),
      'debe ser una URL postgresql://',
    ),
  WEB_ORIGIN: z
    .string()
    .url()
    .transform((value) => new URL(value).origin),
  CSRF_SECRET: z
    .string()
    .refine(
      (value) => Buffer.byteLength(value, 'utf8') >= 32,
      'debe tener al menos 32 bytes',
    )
    .refine(
      (value) => !value.trim().toLowerCase().startsWith('replace-with'),
      'es el valor de ejemplo de .env.example: genere un secreto aleatorio',
    ),
  COOKIE_SECURE: booleanString.default(false),
  TRUST_PROXY: trustProxy.default(false),
  BODY_LIMIT: z
    .string()
    .regex(/^\d+(kb|mb)$/i)
    .default('100kb'),

  SESSION_ABSOLUTE_TTL_MINUTES: positiveInt.default(480),
  SESSION_IDLE_TTL_MINUTES: positiveInt.default(30),

  RATE_LOGIN_IP_LIMIT: positiveInt.default(10),
  RATE_LOGIN_IP_WINDOW_SECONDS: positiveInt.default(60),
  RATE_LOGIN_ACCOUNT_LIMIT: positiveInt.default(5),
  RATE_LOGIN_ACCOUNT_WINDOW_SECONDS: positiveInt.default(900),
  RATE_USER_LIMIT: positiveInt.default(120),
  RATE_USER_WINDOW_SECONDS: positiveInt.default(60),
  RATE_GLOBAL_LIMIT: positiveInt.default(300),
  RATE_GLOBAL_WINDOW_SECONDS: positiveInt.default(60),
});

export interface RateLimitRule {
  limit: number;
  windowSeconds: number;
}

export interface AppConfig {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  databaseUrl: string;
  webOrigin: string;
  csrfSecret: string;
  cookieSecure: boolean;
  trustProxy: false | number;
  bodyLimit: string;
  session: { absoluteTtlMs: number; idleTtlMs: number };
  rateLimits: {
    loginIp: RateLimitRule;
    loginAccount: RateLimitRule;
    user: RateLimitRule;
    global: RateLimitRule;
  };
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Configuración inválida:\n - ${problems.join('\n - ')}`);
    this.name = 'ConfigError';
  }
}

/** Valida el entorno y falla rápido. Nunca incluye valores en el mensaje (pueden ser secretos). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      parsed.error.issues.map(
        (issue) => `${issue.path.join('.') || '(raíz)'}: ${issue.message}`,
      ),
    );
  }
  const e = parsed.data;
  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    databaseUrl: e.DATABASE_URL,
    webOrigin: e.WEB_ORIGIN,
    csrfSecret: e.CSRF_SECRET,
    cookieSecure: e.COOKIE_SECURE,
    trustProxy: e.TRUST_PROXY,
    bodyLimit: e.BODY_LIMIT,
    session: {
      absoluteTtlMs: e.SESSION_ABSOLUTE_TTL_MINUTES * 60_000,
      idleTtlMs: e.SESSION_IDLE_TTL_MINUTES * 60_000,
    },
    rateLimits: {
      loginIp: {
        limit: e.RATE_LOGIN_IP_LIMIT,
        windowSeconds: e.RATE_LOGIN_IP_WINDOW_SECONDS,
      },
      loginAccount: {
        limit: e.RATE_LOGIN_ACCOUNT_LIMIT,
        windowSeconds: e.RATE_LOGIN_ACCOUNT_WINDOW_SECONDS,
      },
      user: {
        limit: e.RATE_USER_LIMIT,
        windowSeconds: e.RATE_USER_WINDOW_SECONDS,
      },
      global: {
        limit: e.RATE_GLOBAL_LIMIT,
        windowSeconds: e.RATE_GLOBAL_WINDOW_SECONDS,
      },
    },
  };
}

/** Raíz del monorepo: apps/api/{src,dist}/config → cuatro niveles arriba. */
export function rootEnvPath(): string {
  return path.resolve(__dirname, '../../../../.env');
}

/** Carga el `.env` de la raíz si existe; las variables ya definidas en el entorno tienen prioridad. */
export function loadRootEnvFile(): void {
  const file = rootEnvPath();
  if (existsSync(file)) process.loadEnvFile(file);
}
