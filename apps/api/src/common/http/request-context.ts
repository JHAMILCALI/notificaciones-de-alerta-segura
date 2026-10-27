import type { Request } from 'express';
import type { Role } from '@alertasegura/shared';

export interface AuthenticatedUser {
  id: string;
  email: string;
  displayName: string;
  role: Role;
}

export interface AuthContext {
  user: AuthenticatedUser;
  sessionId: string;
}

export interface ValidatedInput {
  body?: unknown;
  params?: unknown;
  query?: unknown;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Sesión válida resuelta por AuthenticationGuard (si la hay). */
      auth?: AuthContext;
      /** Entrada ya validada con Zod por ValidationGuard. */
      validated?: ValidatedInput;
      /** Borrador cargado y autorizado por DraftOwnershipGuard. */
      draftId?: string;
    }
  }
}

/** IP del cliente. Express solo confía en X-Forwarded-For si `trust proxy` está activo. */
export function clientIp(req: Request): string {
  const raw = req.ip ?? req.socket.remoteAddress ?? 'unknown';
  return raw.startsWith('::ffff:') ? raw.slice(7) : raw;
}

export function userAgentOf(req: Request): string | null {
  const ua = req.headers['user-agent'];
  return typeof ua === 'string' ? ua.slice(0, 256) : null;
}

export interface RequestMeta {
  ip: string;
  userAgent: string | null;
  method: string;
  path: string;
}

export function requestMeta(req: Request): RequestMeta {
  return {
    ip: clientIp(req),
    userAgent: userAgentOf(req),
    method: req.method,
    // originalUrl sin query: la query puede llevar datos del usuario
    path: (req.originalUrl ?? req.url).split('?')[0] ?? '',
  };
}
