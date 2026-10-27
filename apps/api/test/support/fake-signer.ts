import {
  createHash,
  generateKeyPairSync,
  sign as ecdsaSign,
  type KeyObject,
} from 'node:crypto';
import {
  SignRequestSchema,
  type PublicJwk,
  type SignRequest,
  type SignResponse,
} from '@alertasegura/shared';
import {
  SignerUnavailableError,
  type SignerClient,
} from '../../src/modules/signer/signer.client';

/** JCS (RFC 8785) para los tipos que usan los documentos: objetos, arreglos, cadenas, enteros, booleanos y null. */
export function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(
    ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${jcs(v)}`).join(',')}}`;
}

export type FakeSignerFault =
  /** No responde: lanza SignerUnavailableError como el cliente HTTP ante una caída. */
  | 'down'
  /** Devuelve un hash que no corresponde a los bytes firmados. */
  | 'bad-hash'
  /** Firma un documento distinto del solicitado. */
  | 'other-document';

/**
 * Firmante falso de PRUEBA: mismo contrato que el firmante real (`SignRequestSchema` de entrada y `SignResponse`
 * de salida), con una clave ECDSA P-256 efímera generada en cada instancia. No es el firmante de producción ni
 * comparte código con él; sirve para probar la API sin depender de la implementación de MOTO.
 */
export class FakeSigner implements SignerClient {
  readonly keyId: string;
  readonly publicJwk: PublicJwk;
  /** Documentos recibidos, en orden. */
  readonly calls: SignRequest[] = [];
  /** Falla permanente hasta que se limpie. */
  fault: FakeSignerFault | null = null;
  /** Número de llamadas a `sign` tras las cuales el firmante empieza a caer (para fallar en la 2.ª firma). */
  private failFromCall: number | null = null;
  private readonly privateKey: KeyObject;

  constructor() {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: 'jwk' });
    this.publicJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: jwk.x ?? '',
      y: jwk.y ?? '',
    };
    this.keyId = createHash('sha256')
      .update(publicKey.export({ type: 'spki', format: 'der' }))
      .digest('base64url');
  }

  /** Cae a partir de la llamada número `n` (1 = la primera desde ahora). */
  failFrom(n: number): void {
    this.failFromCall = this.calls.length + n;
  }

  reset(): void {
    this.fault = null;
    this.failFromCall = null;
    this.calls.length = 0;
  }

  /** Lógica de firma, compartida con el servidor HTTP de las pruebas del cliente. */
  signDocument(document: unknown): SignResponse {
    const parsed = SignRequestSchema.safeParse(document);
    if (!parsed.success) throw new Error('INVALID_DOCUMENT');
    const signed =
      this.fault === 'other-document' && parsed.data.tipo_doc === 'ALERTA'
        ? { ...parsed.data, mensaje: 'Mensaje adulterado por el firmante' }
        : parsed.data;
    const payload = jcs({ ...signed, key_id: this.keyId });
    const bytes = Buffer.from(payload, 'utf8');
    return {
      payload_canonico: bytes.toString('base64url'),
      hash_payload:
        this.fault === 'bad-hash'
          ? 'f'.repeat(64)
          : createHash('sha256').update(bytes).digest('hex'),
      firma: ecdsaSign('sha256', bytes, {
        key: this.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('base64url'),
      key_id: this.keyId,
    };
  }

  sign(document: SignRequest): Promise<SignResponse> {
    this.calls.push(document);
    if (
      this.fault === 'down' ||
      (this.failFromCall !== null && this.calls.length >= this.failFromCall)
    ) {
      return Promise.reject(new SignerUnavailableError('firmante falso caído'));
    }
    try {
      return Promise.resolve(this.signDocument(document));
    } catch {
      return Promise.reject(new SignerUnavailableError('documento inválido'));
    }
  }
}
