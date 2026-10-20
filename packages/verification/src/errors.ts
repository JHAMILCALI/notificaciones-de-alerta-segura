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
  | 'PRIVATE_KEY_REJECTED';

export class VerificationError extends Error {
  readonly code: VerificationErrorCode;

  constructor(code: VerificationErrorCode, message: string) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
  }
}
