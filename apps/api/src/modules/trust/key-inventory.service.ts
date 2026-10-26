import { createHash, createPublicKey } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
} from '@nestjs/common';
import {
  ManifiestoDocumentoSchema,
  SignedEnvelopeSchema,
  type PublicJwk,
} from '@alertasegura/shared';
import { APP_CONFIG, type AppConfig } from '../../config/config.module';
import { PrismaService } from '../../database/prisma.service';

const MAX_MANIFEST_BYTES = 256 * 1024;

/** `key_id` = SHA-256 (base64url) de la SPKI DER de la clave pública (documents.ts de shared). */
function keyIdOf(jwk: PublicJwk): string | null {
  try {
    const spki = createPublicKey({ key: jwk, format: 'jwk' }).export({
      type: 'spki',
      format: 'der',
    });
    return createHash('sha256').update(spki).digest('base64url');
  } catch {
    return null;
  }
}

export interface InventoryResult {
  /** Claves nuevas insertadas en la tabla. */
  inserted: number;
  /** Claves del manifiesto que ya estaban registradas. */
  known: number;
  /** Claves descartadas por no cumplir el contrato (key_id que no corresponde a su JWK). */
  rejected: number;
}

/**
 * Inventario de claves públicas (S2-25). Al arrancar lee el manifiesto de confianza y registra en `ClavePublica`
 * las claves que aún no estén (solo INSERT: el rol de la app no puede modificar ni borrar filas).
 *
 * NO es una autoridad de confianza. La API no conoce la raíz y no verifica la firma del manifiesto; la tabla es
 * metadato de consulta (qué claves se han visto y en qué versión). Quien decide qué clave vale es el cliente, que
 * verifica el manifiesto firmado contra la raíz. Una fila en esta tabla nunca autoriza nada por sí misma.
 */
@Injectable()
export class KeyInventoryService implements OnApplicationBootstrap {
  private readonly logger = new Logger(KeyInventoryService.name);

  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly prisma: PrismaService,
  ) {}

  /** Nunca impide arrancar: sin manifiesto o con uno ilegible la API sigue (y /trust/manifest da 503). */
  async onApplicationBootstrap(): Promise<void> {
    try {
      const result = await this.sync();
      if (result) {
        this.logger.log(
          `Inventario de claves públicas: ${result.inserted} nueva(s), ${result.known} ya registrada(s), ${result.rejected} descartada(s)`,
        );
      }
    } catch (error) {
      this.logger.warn(
        `No se pudo actualizar el inventario de claves: ${
          error instanceof Error ? error.message : 'error desconocido'
        }`,
      );
    }
  }

  /** Devuelve null si no hay manifiesto configurado. */
  async sync(): Promise<InventoryResult | null> {
    const file = this.config.trustManifestFile;
    if (!file) return null;
    const info = await stat(file);
    if (!info.isFile() || info.size > MAX_MANIFEST_BYTES) {
      throw new Error('el archivo del manifiesto no es válido');
    }
    const envelope = SignedEnvelopeSchema.parse(
      JSON.parse(await readFile(file, 'utf8')),
    );
    const bytes = Buffer.from(envelope.payload_canonico, 'base64url');
    if (
      createHash('sha256').update(bytes).digest('hex') !== envelope.hash_payload
    ) {
      throw new Error('hash_payload del manifiesto no corresponde a sus bytes');
    }
    const manifest = ManifiestoDocumentoSchema.parse(
      JSON.parse(bytes.toString('utf8')),
    );

    const valid = manifest.claves.filter(
      (clave) => keyIdOf(clave.jwk) === clave.key_id,
    );
    const known = await this.prisma.clavePublica.findMany({
      where: { keyId: { in: valid.map((c) => c.key_id) } },
      select: { keyId: true },
    });
    const knownIds = new Set(known.map((k) => k.keyId));
    const fresh = valid.filter((c) => !knownIds.has(c.key_id));
    if (fresh.length > 0) {
      // skipDuplicates = ON CONFLICT DO NOTHING: necesita solo INSERT, y dos arranques simultáneos no chocan.
      await this.prisma.clavePublica.createMany({
        data: fresh.map((c) => ({
          keyId: c.key_id,
          jwk: c.jwk,
          versionRegistro: manifest.version,
        })),
        skipDuplicates: true,
      });
    }
    return {
      inserted: fresh.length,
      known: knownIds.size,
      rejected: manifest.claves.length - valid.length,
    };
  }
}
