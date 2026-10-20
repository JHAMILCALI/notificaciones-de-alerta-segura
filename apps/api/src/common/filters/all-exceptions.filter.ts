import {
  Catch,
  Logger,
  type ArgumentsHost,
  type ExceptionFilter,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { mapError } from './error-mapper';

/** Filtro global: formato `ApiError`, `Retry-After` en 429 y cero filtración de detalles internos. */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('Exceptions');

  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const res = http.getResponse<Response>();
    const req = http.getRequest<Request>();
    const mapped = mapError(exception);

    if (mapped.unexpected) {
      // La traza queda solo en el log del servidor.
      this.logger.error(
        `${req.method} ${(req.originalUrl ?? '').split('?')[0]} -> 500`,
        exception instanceof Error ? exception.stack : String(exception),
      );
    }
    if (res.headersSent) return;
    if (mapped.retryAfterSeconds !== undefined) {
      res.setHeader('Retry-After', String(mapped.retryAfterSeconds));
    }
    res.status(mapped.status).json(mapped.body);
  }
}
