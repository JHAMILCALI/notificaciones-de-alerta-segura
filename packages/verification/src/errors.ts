/** Códigos de fallo de la canonicalización JCS (RFC 8785 / I-JSON). */
export type CanonicalizationErrorCode =
  | 'UNSUPPORTED_TYPE'
  | 'NON_FINITE_NUMBER'
  | 'LONE_SURROGATE'
  | 'CYCLE'
  | 'MAX_DEPTH';

export class CanonicalizationError extends Error {
  readonly code: CanonicalizationErrorCode;

  constructor(code: CanonicalizationErrorCode, message: string) {
    super(message);
    this.name = 'CanonicalizationError';
    this.code = code;
  }
}

/** Códigos de fallo de las utilidades criptográficas. */
export type VerificationErrorCode =
  | 'INVALID_BASE64URL'
  | 'INVALID_PUBLIC_KEY'
  | 'PRIVATE_KEY_REJECTED'
  // Verificación de documentos firmados (semana 2)
  | 'INVALID_ENVELOPE'
  | 'KEY_ID_MISMATCH'
  | 'HASH_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'NOT_CANONICAL'
  | 'INVALID_PAYLOAD'
  | 'TIPO_DOC_MISMATCH'
  | 'MANIFEST_EXPIRED'
  | 'MANIFEST_TOO_LONG'
  | 'MANIFEST_VERSION_TOO_LOW'
  | 'MANIFEST_INCONSISTENT'
  // Cancelación (EVENTO sobre una ALERTA)
  | 'CANCELACION_ALERTA_MISMATCH'
  | 'CANCELACION_HASH_MISMATCH'
  | 'CANCELACION_EMISOR_MISMATCH';

export class VerificationError extends Error {
  readonly code: VerificationErrorCode;

  constructor(code: VerificationErrorCode, message: string) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
  }
}
