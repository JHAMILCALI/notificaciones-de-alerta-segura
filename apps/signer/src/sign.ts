import { createHash, sign } from 'node:crypto';
import {
  ESTADO_FRESCURA_MAX_SEGUNDOS,
  SignRequestSchema,
  SignResponseSchema,
  type SignRequest,
  type SignResponse,
} from '@alertasegura/shared';
import { bytesToBase64Url, canonicalize } from '@alertasegura/verification';
import type { LoadedKey } from './key.ts';

/** Fallo de validación del documento. El mensaje lleva rutas de campos, nunca valores. */
export class InvalidDocumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidDocumentError';
  }
}

/** Campos de fecha de cada tipo, que el firmante normaliza antes de canonicalizar. */
const DATE_FIELDS = {
  ALERTA: ['emitida_en', 'expira_en'],
  EVENTO: ['emitida_en'],
  ESTADO: ['issued_at', 'expires_at'],
} as const;

/** Normaliza a ISO 8601 UTC con segundos. Rechaza fechas que el formato admite pero el calendario no (2026-02-30). */
function normalizeDate(value: string, field: string): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new InvalidDocumentError(`Fecha no válida en ${field}`);
  const normalized = new Date(time).toISOString().replace(/\.\d{3}Z$/, 'Z');
  if (normalized !== value) throw new InvalidDocumentError(`Fecha no válida en ${field}`);
  return normalized;
}

/** Valida con el esquema estricto del contrato y devuelve el documento con fechas normalizadas. */
export function parseSignRequest(input: unknown): SignRequest {
  const parsed = SignRequestSchema.safeParse(input);
  if (!parsed.success) {
    const paths = [...new Set(parsed.error.issues.map((i) => i.path.join('.') || '(documento)'))];
    throw new InvalidDocumentError(`Documento no válido en: ${paths.join(', ')}`);
  }
  const document: SignRequest = { ...parsed.data };
  const record = document as Record<string, unknown>;
  for (const field of DATE_FIELDS[document.tipo_doc]) {
    record[field] = normalizeDate(String(record[field]), field);
  }

  if (document.tipo_doc === 'ALERTA' && Date.parse(document.expira_en) <= Date.parse(document.emitida_en)) {
    throw new InvalidDocumentError('expira_en debe ser posterior a emitida_en');
  }
  if (document.tipo_doc === 'ESTADO') {
    const seconds = (Date.parse(document.expires_at) - Date.parse(document.issued_at)) / 1000;
    if (seconds <= 0 || seconds > ESTADO_FRESCURA_MAX_SEGUNDOS) {
      throw new InvalidDocumentError(`expires_at debe estar entre 1 y ${ESTADO_FRESCURA_MAX_SEGUNDOS} s después de issued_at`);
    }
  }
  return document;
}

/**
 * Añade el `key_id` de la clave activa, canonicaliza con JCS (la misma implementación que verifica),
 * firma con ECDSA P-256/SHA-256 en IEEE P1363 y devuelve el sobre.
 */
export function signDocument(request: SignRequest, key: LoadedKey): SignResponse {
  const bytes = Buffer.from(canonicalize({ ...request, key_id: key.keyId }), 'utf8');
  const signature = sign('sha256', bytes, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return SignResponseSchema.parse({
    payload_canonico: bytesToBase64Url(bytes),
    hash_payload: createHash('sha256').update(bytes).digest('hex'),
    firma: bytesToBase64Url(signature),
    key_id: key.keyId,
  });
}
