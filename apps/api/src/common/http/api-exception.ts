import { HttpException } from '@nestjs/common';
import type { ApiError, ApiErrorCode } from '@alertasegura/shared';

type Issue = NonNullable<ApiError['issues']>[number];

/** Excepción con el formato `ApiError` del contrato. */
export class ApiException extends HttpException {
  constructor(
    statusCode: number,
    public readonly code: ApiErrorCode,
    message: string,
    public readonly issues?: Issue[],
    public readonly retryAfterSeconds?: number,
  ) {
    super({ statusCode, code, message }, statusCode);
  }

  toBody(): ApiError {
    const body: ApiError = {
      statusCode: this.getStatus(),
      code: this.code,
      message: this.message,
    };
    if (this.issues) body.issues = this.issues;
    return body;
  }
}

export const unauthenticated = (): ApiException =>
  new ApiException(401, 'UNAUTHENTICATED', 'Autenticación requerida');
export const invalidCredentials = (): ApiException =>
  new ApiException(401, 'INVALID_CREDENTIALS', 'Credenciales inválidas');
export const csrfInvalid = (): ApiException =>
  new ApiException(403, 'CSRF_INVALID', 'Token CSRF ausente o inválido');
export const forbidden = (): ApiException =>
  new ApiException(
    403,
    'FORBIDDEN',
    'No tiene permiso para realizar esta acción',
  );
export const notFound = (): ApiException =>
  new ApiException(404, 'NOT_FOUND', 'Recurso no encontrado');
export const conflict = (message: string): ApiException =>
  new ApiException(409, 'CONFLICT', message);
export const rateLimited = (retryAfterSeconds: number): ApiException =>
  new ApiException(
    429,
    'RATE_LIMITED',
    'Demasiadas solicitudes',
    undefined,
    retryAfterSeconds,
  );
export const validationFailed = (
  issues: Issue[],
  statusCode = 400,
): ApiException =>
  new ApiException(
    statusCode,
    'VALIDATION_FAILED',
    'La solicitud no es válida',
    issues,
  );

/** 503: el firmante no responde o devolvió algo inconsistente; no se escribió nada. */
export const signerUnavailable = (): ApiException =>
  new ApiException(
    503,
    'SIGNER_UNAVAILABLE',
    'El servicio de firma no está disponible; inténtelo de nuevo más tarde',
  );
