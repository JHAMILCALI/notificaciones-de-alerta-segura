import { readFile, stat } from 'node:fs/promises';
import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  SignedEnvelopeSchema,
  type TrustManifestResponse,
} from '@alertasegura/shared';
import { ApiException } from '../../common/http/api-exception';
import { APP_CONFIG, type AppConfig } from '../../config/config.module';

/** Un manifiesto firmado ocupa unos pocos KB; un archivo enorme es un error de configuración. */
const MAX_MANIFEST_BYTES = 256 * 1024;

/**
 * Sirve el manifiesto de confianza tal como lo emitió la CLI offline: la API no lo firma, no lo modifica ni
 * lo interpreta (la verificación contra la raíz es del cliente). Solo comprueba que el archivo tenga la forma
 * de un sobre firmado y lo relee en cada petición, así un manifiesto nuevo o una revocación se publican con
 * solo reemplazar el archivo, sin reiniciar la API.
 */
@Injectable()
export class TrustService {
  private readonly logger = new Logger(TrustService.name);

  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  async manifest(): Promise<TrustManifestResponse> {
    const file = this.config.trustManifestFile;
    if (!file)
      throw this.unavailable('TRUST_MANIFEST_FILE no está configurado');
    try {
      const info = await stat(file);
      if (!info.isFile() || info.size > MAX_MANIFEST_BYTES) {
        throw this.unavailable('el archivo del manifiesto no es válido');
      }
      const parsed = SignedEnvelopeSchema.safeParse(
        JSON.parse(await readFile(file, 'utf8')),
      );
      if (!parsed.success) {
        throw this.unavailable(
          'el manifiesto no tiene la forma de un sobre firmado',
        );
      }
      return { manifiesto: parsed.data };
    } catch (error) {
      if (error instanceof ApiException) throw error;
      throw this.unavailable('no se pudo leer el manifiesto');
    }
  }

  /** El motivo va al log del servidor; al cliente solo le llega un mensaje genérico. */
  private unavailable(reason: string): ApiException {
    this.logger.warn(`Manifiesto de confianza no disponible: ${reason}`);
    return new ApiException(
      503,
      'TRUST_MANIFEST_UNAVAILABLE',
      'El manifiesto de confianza no está disponible',
    );
  }
}
