import { randomBytes, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { SignResponseSchema } from '@alertasegura/shared';
import { buildAlertaRequest } from '../src/modules/alerts/documents';
import {
  HttpSignerClient,
  SignerUnavailableError,
} from '../src/modules/signer/signer.client';
import { FakeSigner } from './support/fake-signer';
import { expectValid, verifyWithPackage } from './support/verify';

/** En Windows el canal es una named pipe; en Linux/macOS, un socket Unix: la API usa `socketPath` en ambos. */
function newSocketPath(): string {
  const name = `alertasegura-test-${randomBytes(6).toString('hex')}`;
  return process.platform === 'win32'
    ? ['\\\\.', 'pipe', name].join('\\')
    : path.join(tmpdir(), `${name}.sock`);
}

type Behavior =
  | 'ok'
  | 'hang'
  | 'http-500'
  | 'invalid-document'
  | 'not-json'
  | 'out-of-contract'
  | 'huge';

describe('S2-20: cliente HTTP del firmante sobre socket (firmante falso del mismo contrato)', () => {
  const fake = new FakeSigner();
  const socketPath = newSocketPath();
  const requests: Array<{ method?: string; url?: string; body: string }> = [];
  let behavior: Behavior = 'ok';
  let server: Server;

  const draft = {
    ownerId: randomUUID(),
    tipo: 'GRANIZADA',
    departamento: 'COCHABAMBA',
    municipio: null,
    severidad: 'AMARILLA',
    mensaje: 'Granizada aislada por la tarde en el valle alto.',
    vigenciaHoras: 6,
  } as const;
  const document = () =>
    buildAlertaRequest(draft, randomUUID(), new Date('2026-10-26T14:00:00Z'));

  const client = (timeoutMs = 3000) =>
    new HttpSignerClient(socketPath, timeoutMs);

  beforeAll(async () => {
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        requests.push({ method: req.method, url: req.url, body });
        const json = (status: number, payload: unknown) => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(payload));
        };
        switch (behavior) {
          case 'hang':
            return; // nunca responde
          case 'http-500':
            return json(500, { code: 'INTERNAL_ERROR', message: 'fallo' });
          case 'invalid-document':
            return json(400, { code: 'INVALID_DOCUMENT', message: 'inválido' });
          case 'not-json':
            res.writeHead(200);
            return res.end('esto no es JSON');
          case 'out-of-contract':
            return json(200, { payload_canonico: 'abc', key_id: 'x' });
          case 'huge':
            res.writeHead(200, { 'content-type': 'application/json' });
            return res.end('x'.repeat(200 * 1024));
          default:
            return json(200, fake.signDocument(JSON.parse(body)));
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  beforeEach(() => {
    behavior = 'ok';
    requests.length = 0;
  });

  it('POST /sign por el socket: devuelve un sobre que cumple SignResponseSchema y que verifica @alertasegura/verification', async () => {
    const doc = document();
    const response = await client().sign(doc);

    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ method: 'POST', url: '/sign' });
    expect(JSON.parse(requests[0]?.body ?? '')).toEqual(doc); // se envía el documento sin key_id
    expect(SignResponseSchema.safeParse(response).success).toBe(true);

    const [verified] = verifyWithPackage([response], fake.publicJwk);
    expectValid(verified);
    expect(verified?.document).toMatchObject({
      tipo_doc: 'ALERTA',
      alerta_id: doc.alerta_id,
      key_id: fake.keyId,
    });
  });

  it('nadie escucha en el socket → SignerUnavailableError sin esperar el tiempo máximo', async () => {
    const absent = new HttpSignerClient(newSocketPath(), 3000);
    const started = Date.now();
    await expect(absent.sign(document())).rejects.toBeInstanceOf(
      SignerUnavailableError,
    );
    expect(Date.now() - started).toBeLessThan(1500);
  });

  it('el firmante no responde → SignerUnavailableError al cumplirse el tiempo máximo', async () => {
    behavior = 'hang';
    const started = Date.now();
    await expect(client(300).sign(document())).rejects.toBeInstanceOf(
      SignerUnavailableError,
    );
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(250);
    expect(elapsed).toBeLessThan(2000);
  });

  it.each<[string, Behavior]>([
    ['HTTP 500', 'http-500'],
    ['400 INVALID_DOCUMENT', 'invalid-document'],
    ['una respuesta que no es JSON', 'not-json'],
    ['una respuesta fuera de contrato', 'out-of-contract'],
    ['una respuesta desmesurada', 'huge'],
  ])(
    '%s → SignerUnavailableError (nunca se propaga el detalle del firmante)',
    async (_name, mode) => {
      behavior = mode;
      const error: unknown = await client()
        .sign(document())
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(SignerUnavailableError);
      expect(JSON.stringify(error)).not.toContain(draft.mensaje);
    },
  );

  it('el firmante cae y se recupera: la siguiente petición vuelve a funcionar', async () => {
    behavior = 'http-500';
    await expect(client().sign(document())).rejects.toBeInstanceOf(
      SignerUnavailableError,
    );
    behavior = 'ok';
    await expect(client().sign(document())).resolves.toMatchObject({
      key_id: fake.keyId,
    });
  });
});
