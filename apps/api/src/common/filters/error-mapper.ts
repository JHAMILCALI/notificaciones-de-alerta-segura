import { HttpException } from '@nestjs/common';
import type { ApiError, ApiErrorCode } from '@alertasegura/shared';
import { ApiException } from '../http/api-exception';

export interface MappedError {
  status: number;
  body: ApiError;
  retryAfterSeconds?: number;
  /** true cuando el fallo es inesperado y debe registrarse en el log del servidor. */
  unexpected: boolean;
}

const MESSAGES: Record<number, { code: ApiErrorCode; message: string }> = {
  400: { code: 'VALIDATION_FAILED', message: 'La solicitud no es válida' },
  401: { code: 'UNAUTHENTICATED', message: 'Autenticación requerida' },
  403: {
    code: 'FORBIDDEN',
    message: 'No tiene permiso para realizar esta acción',
  },
  404: { code: 'NOT_FOUND', message: 'Recurso no encontrado' },
  405: { code: 'NOT_FOUND', message: 'Recurso no encontrado' },
  409: {
    code: 'CONFLICT',
    message: 'Conflicto con el estado actual del recurso',
  },
  413: {
    code: 'VALIDATION_FAILED',
    message: 'El cuerpo de la solicitud es demasiado grande',
  },
  415: { code: 'VALIDATION_FAILED', message: 'Tipo de contenido no admitido' },
  429: { code: 'RATE_LIMITED', message: 'Demasiadas solicitudes' },
};

function clientErrorBody(status: number): ApiError {
  const mapped = MESSAGES[status] ?? MESSAGES[400];
  return { statusCode: status, code: mapped.code, message: mapped.message };
}

/** Convierte cualquier error en un `ApiError` sin trazas, sin mensajes de Prisma ni detalles internos. */
export function mapError(error: unknown): MappedError {
  if (error instanceof ApiException) {
    return {
      status: error.getStatus(),
      body: error.toBody(),
      retryAfterSeconds: error.retryAfterSeconds,
      unexpected: false,
    };
  }
  if (error instanceof HttpException) {
    const status = error.getStatus();
    if (status >= 500) return internal();
    return { status, body: clientErrorBody(status), unexpected: false };
  }
  // Errores de body-parser / http-errors: traen `status` o `statusCode` 4xx y `expose`.
  if (typeof error === 'object' && error !== null) {
    const candidate = error as { status?: unknown; statusCode?: unknown };
    const status =
      typeof candidate.status === 'number'
        ? candidate.status
        : candidate.statusCode;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      return { status, body: clientErrorBody(status), unexpected: false };
    }
  }
  return internal();
}

function internal(): MappedError {
  return {
    status: 500,
    body: {
      statusCode: 500,
      code: 'INTERNAL_ERROR',
      message: 'Error interno del servidor',
    },
    unexpected: true,
  };
}
