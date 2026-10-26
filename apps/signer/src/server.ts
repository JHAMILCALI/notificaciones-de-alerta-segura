import { chmodSync, lstatSync, unlinkSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { SignerHealthSchema, type SignerError } from '@alertasegura/shared';
import type { LoadedKey } from './key.ts';
import { InvalidDocumentError, parseSignRequest, signDocument } from './sign.ts';

/** Límite del cuerpo de `POST /sign` (contrato del firmante). */
export const MAX_BODY_BYTES = 16 * 1024;

/** Eventos de registro: solo metadatos, nunca el payload ni la clave. */
export interface SignerLogger {
  info(event: string, fields?: Record<string, string | number>): void;
  error(event: string, fields?: Record<string, string | number>): void;
}

export const consoleLogger: SignerLogger = {
  info: (event, fields) => console.log(JSON.stringify({ level: 'info', event, ...fields })),
  error: (event, fields) => console.error(JSON.stringify({ level: 'error', event, ...fields })),
};

export interface SignerServerOptions {
  /** `null` si la clave no pudo cargarse: el servicio responde 503 `KEY_UNAVAILABLE`. */
  key: LoadedKey | null;
  logger?: SignerLogger;
}

class BodyTooLargeError extends Error {}

function sendJson(res: ServerResponse, status: number, body: unknown, close = false): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
    ...(close ? { connection: 'close' } : {}),
  });
  res.end(text);
}

function sendError(res: ServerResponse, status: number, error: SignerError, close = false): void {
  sendJson(res, status, error, close);
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      reject(new BodyTooLargeError());
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new BodyTooLargeError());
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function createSignerServer(options: SignerServerOptions): Server {
  const logger = options.logger ?? consoleLogger;
  const { key } = options;

  const server = createServer((req, res) => {
    void handle(req, res).catch(() => {
      // Sin trazas ni rutas de archivos en la respuesta.
      logger.error('internal_error');
      if (!res.headersSent) sendError(res, 500, { code: 'INTERNAL_ERROR', message: 'Error interno del firmante' });
      else res.destroy();
    });
  });

  // Protección frente a clientes lentos o colgados.
  server.headersTimeout = 5_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? '').split('?')[0];

    if (path === '/health') {
      if (req.method !== 'GET') return sendError(res, 405, { code: 'INVALID_DOCUMENT', message: 'Método no permitido' });
      if (key === null) return sendError(res, 503, { code: 'KEY_UNAVAILABLE', message: 'Clave de firma no disponible' });
      const health = SignerHealthSchema.parse({ status: 'ok', key_id: key.keyId });
      return sendJson(res, 200, health);
    }

    if (path === '/sign') {
      if (req.method !== 'POST') return sendError(res, 405, { code: 'INVALID_DOCUMENT', message: 'Método no permitido' });
      if (key === null) {
        // No se lee el cuerpo: sin clave no hay nada que hacer con él.
        logger.error('key_unavailable');
        return sendError(res, 503, { code: 'KEY_UNAVAILABLE', message: 'Clave de firma no disponible' }, true);
      }

      let body: Buffer;
      try {
        body = await readBody(req);
      } catch (error) {
        if (error instanceof BodyTooLargeError) {
          logger.info('rejected', { reason: 'body_too_large' });
          return sendError(res, 413, { code: 'INVALID_DOCUMENT', message: 'Cuerpo demasiado grande (máximo 16 kB)' }, true);
        }
        throw error;
      }

      let json: unknown;
      try {
        json = JSON.parse(body.toString('utf8'));
      } catch {
        logger.info('rejected', { reason: 'invalid_json' });
        return sendError(res, 400, { code: 'INVALID_DOCUMENT', message: 'El cuerpo no es JSON válido' });
      }

      let request;
      try {
        request = parseSignRequest(json);
      } catch (error) {
        if (error instanceof InvalidDocumentError) {
          logger.info('rejected', { reason: 'invalid_document' });
          return sendError(res, 400, { code: 'INVALID_DOCUMENT', message: error.message });
        }
        throw error;
      }

      const envelope = signDocument(request, key);
      logger.info('signed', { tipo_doc: request.tipo_doc, key_id: key.keyId, hash_payload: envelope.hash_payload });
      return sendJson(res, 200, envelope);
    }

    return sendError(res, 404, { code: 'INVALID_DOCUMENT', message: 'Ruta no encontrada' });
  }

  return server;
}

/** Escucha en el socket Unix (0660) o en la named pipe de Windows. Devuelve cuando ya acepta conexiones. */
export function listenOnSocket(server: Server, socketPath: string): Promise<void> {
  const isPipe = process.platform === 'win32' && socketPath.startsWith('\\\\.\\pipe\\');
  if (!isPipe) removeStaleSocket(socketPath);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    // El socket nace con 0660 (umask 0117) y además se fija después: no hay ventana con permisos más abiertos.
    const previousUmask = isPipe ? undefined : process.umask(0o117);
    server.listen(socketPath, () => {
      if (previousUmask !== undefined) process.umask(previousUmask);
      server.off('error', reject);
      if (!isPipe && process.platform !== 'win32') chmodSync(socketPath, 0o660);
      resolve();
    });
  });
}

/** Elimina un socket huérfano de una ejecución anterior; nunca borra algo que no sea un socket. */
function removeStaleSocket(socketPath: string): void {
  try {
    if (lstatSync(socketPath).isSocket()) unlinkSync(socketPath);
  } catch {
    // No existe: nada que limpiar.
  }
}
