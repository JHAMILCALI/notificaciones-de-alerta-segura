import { request } from 'node:http';
import { Logger } from '@nestjs/common';
import {
  SignResponseSchema,
  type SignRequest,
  type SignResponse,
} from '@alertasegura/shared';

export const SIGNER_CLIENT = Symbol('SIGNER_CLIENT');

/** El firmante no respondió a tiempo, devolvió un error o una respuesta fuera de contrato. */
export class SignerUnavailableError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'SignerUnavailableError';
  }
}

/** Puerto hacia el firmante aislado. Las pruebas lo sustituyen por un firmante falso del mismo contrato. */
export interface SignerClient {
  /** Devuelve el sobre firmado o lanza `SignerUnavailableError`; nunca otro tipo de error. */
  sign(document: SignRequest): Promise<SignResponse>;
}

/** Tope de la respuesta: un sobre firmado ocupa unos pocos KB. */
const MAX_RESPONSE_BYTES = 64 * 1024;

/**
 * Cliente HTTP sobre socket Unix (en Windows, named pipe) del firmante (`POST /sign`). Cualquier fallo
 * (conexión, tiempo, estado distinto de 200, JSON o contrato inválido) termina en `SignerUnavailableError`,
 * sin detalles internos hacia el cliente.
 */
export class HttpSignerClient implements SignerClient {
  private readonly logger = new Logger(HttpSignerClient.name);

  constructor(
    private readonly socketPath: string,
    private readonly timeoutMs: number,
  ) {}

  sign(document: SignRequest): Promise<SignResponse> {
    const body = JSON.stringify(document);
    return new Promise<SignResponse>((resolve, reject) => {
      let settled = false;
      const fail = (reason: string): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.logger.warn(`Firmante no disponible: ${reason}`);
        reject(new SignerUnavailableError(reason));
      };
      const succeed = (value: SignResponse): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };

      const req = request(
        {
          socketPath: this.socketPath,
          path: '/sign',
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              req.destroy();
              fail('respuesta demasiado grande');
              return;
            }
            chunks.push(chunk);
          });
          res.on('error', () => fail('error al leer la respuesta'));
          res.on('end', () => {
            if (res.statusCode !== 200) {
              fail(`estado HTTP ${String(res.statusCode)}`);
              return;
            }
            let json: unknown;
            try {
              json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch {
              fail('respuesta que no es JSON');
              return;
            }
            const parsed = SignResponseSchema.safeParse(json);
            if (!parsed.success) {
              fail('respuesta fuera de contrato');
              return;
            }
            succeed(parsed.data);
          });
        },
      );

      // Plazo total de la operación (conectar, enviar y recibir), no solo de inactividad del socket.
      const timer = setTimeout(() => {
        req.destroy();
        fail(`sin respuesta en ${this.timeoutMs} ms`);
      }, this.timeoutMs);
      req.on('error', (error: NodeJS.ErrnoException) =>
        fail(`conexión fallida (${error.code ?? 'sin código'})`),
      );
      req.end(body);
    });
  }
}
