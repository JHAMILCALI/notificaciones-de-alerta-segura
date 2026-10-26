import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { Inject, Injectable } from '@nestjs/common';
import type { SignRequest, SignResponse } from '@alertasegura/shared';
import {
  SIGNER_CLIENT,
  SignerUnavailableError,
  type SignerClient,
} from '../signer/signer.client';

export interface SignedDocument {
  envelope: SignResponse;
  /** Bytes canónicos exactos que firmó el firmante: son los que se guardan, nunca se reconstruyen. */
  bytes: Uint8Array<ArrayBuffer>;
  /** Contenido ya interpretado de `bytes`. */
  payload: unknown;
}

/**
 * Pide la firma y NO confía a ciegas en la respuesta: comprueba que los bytes decodifican bien, que el
 * SHA-256 es el de esos bytes y que el documento firmado es exactamente el solicitado (más el `key_id`).
 * Un firmante que responda otra cosa se trata como no disponible y no se guarda nada.
 */
@Injectable()
export class SigningService {
  constructor(@Inject(SIGNER_CLIENT) private readonly signer: SignerClient) {}

  async sign(document: SignRequest): Promise<SignedDocument> {
    const envelope = await this.signer.sign(document);

    // Copia a un Uint8Array propio: es el tipo que Prisma acepta para una columna bytea.
    const bytes = new Uint8Array(
      Buffer.from(envelope.payload_canonico, 'base64url'),
    );
    if (
      Buffer.from(bytes).toString('base64url') !== envelope.payload_canonico
    ) {
      throw new SignerUnavailableError('payload_canonico mal codificado');
    }
    const hash = createHash('sha256').update(bytes).digest('hex');
    if (hash !== envelope.hash_payload) {
      throw new SignerUnavailableError(
        'hash_payload no corresponde a los bytes',
      );
    }
    let payload: unknown;
    try {
      payload = JSON.parse(Buffer.from(bytes).toString('utf8'));
    } catch {
      throw new SignerUnavailableError('payload_canonico no es JSON');
    }
    if (!isDeepStrictEqual(payload, { ...document, key_id: envelope.key_id })) {
      throw new SignerUnavailableError(
        'el documento firmado no es el solicitado',
      );
    }
    return { envelope, bytes, payload };
  }
}
