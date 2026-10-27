import { createHash } from 'node:crypto';
import type TestAgent from 'supertest/lib/agent';
import {
  AlertaResponseSchema,
  CSRF_HEADER,
  DraftResponseSchema,
  type AlertaPublicada,
} from '@alertasegura/shared';
import { API, validDraftBody } from './app';

export interface Session {
  agent: TestAgent;
  csrfToken: string;
}

/** Crea un borrador por la API (como lo haría el formulario del emisor) y devuelve su id. */
export async function apiCreateDraft(
  session: Session,
  body: object = validDraftBody,
): Promise<string> {
  const res = await session.agent
    .post(`${API}/drafts`)
    .set(CSRF_HEADER, session.csrfToken)
    .send(body)
    .expect(201);
  return DraftResponseSchema.parse(res.body).draft.id;
}

export function apiPublish(session: Session, draftId: string) {
  return session.agent
    .post(`${API}/drafts/${draftId}/publish`)
    .set(CSRF_HEADER, session.csrfToken);
}

export function apiCancel(session: Session, alertaId: string) {
  return session.agent
    .post(`${API}/alerts/${alertaId}/cancel`)
    .set(CSRF_HEADER, session.csrfToken)
    .send({});
}

/** Crea un borrador y lo publica; devuelve la alerta publicada. */
export async function apiPublishNew(
  session: Session,
  body: object = validDraftBody,
): Promise<AlertaPublicada> {
  const draftId = await apiCreateDraft(session, body);
  const res = await apiPublish(session, draftId).expect(201);
  return AlertaResponseSchema.parse(res.body).alerta;
}

export const sha256Hex = (bytes: Uint8Array): string =>
  createHash('sha256').update(bytes).digest('hex');

export const decodeB64u = (value: string): Buffer =>
  Buffer.from(value, 'base64url');

/** Documento JSON dentro de un sobre firmado (sin verificar la firma: para leer campos en las pruebas). */
export function documentOf(envelope: {
  payload_canonico: string;
}): Record<string, unknown> {
  return JSON.parse(
    decodeB64u(envelope.payload_canonico).toString('utf8'),
  ) as Record<string, unknown>;
}
