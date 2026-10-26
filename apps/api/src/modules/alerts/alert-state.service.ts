import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  EstadoDocumentoSchema,
  type EstadoAlertaValor,
} from '@alertasegura/shared';
import { CLOCK, type Clock } from '../../common/clock/clock';
import { signerUnavailable } from '../../common/http/api-exception';
import { PrismaService } from '../../database/prisma.service';
import { SignerUnavailableError } from '../signer/signer.client';
import type { AlertaRow, EstadoRow } from './alerts.mapper';
import { buildEstadoRequest, type EstadoContent } from './documents';
import { SigningService } from './signing.service';

/** Un estado que caduca en menos de este margen se regenera antes de servirlo. */
export const ESTADO_MARGEN_MS = 30_000;

/**
 * Estado firmado de corta duración (§07.3). Se sirve el último guardado mientras le queden más de 30 s y siga
 * describiendo la alerta; si no, se firma uno nuevo con las fechas actuales y se guarda (solo INSERT).
 */
@Injectable()
export class AlertStateService {
  private readonly logger = new Logger(AlertStateService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly signing: SigningService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /** Qué debe decir hoy el estado de la alerta: la cancelación manda sobre el vencimiento. */
  expectedContent(alerta: AlertaRow, now: Date): EstadoContent {
    if (alerta.evento) {
      return {
        estado: 'CANCELADA',
        secuencia: 1,
        ultimoEventoHash: alerta.evento.hashEvento,
      };
    }
    const estado: EstadoAlertaValor =
      now.getTime() >= alerta.expiraEn.getTime() ? 'VENCIDA' : 'VIGENTE';
    return { estado, secuencia: 0, ultimoEventoHash: null };
  }

  private describes(row: EstadoRow, expected: EstadoContent): boolean {
    try {
      const parsed = EstadoDocumentoSchema.safeParse(
        JSON.parse(Buffer.from(row.payloadCanonico).toString('utf8')),
      );
      return (
        parsed.success &&
        parsed.data.estado === expected.estado &&
        parsed.data.secuencia === expected.secuencia &&
        parsed.data.ultimo_evento_hash === expected.ultimoEventoHash
      );
    } catch {
      return false;
    }
  }

  /**
   * Estado fresco de una alerta. Si hay que regenerarlo y el firmante no responde, se devuelve el último
   * estado guardado aunque esté caducado: sigue siendo un documento firmado auténtico y quien lo verifica
   * decide por su `expires_at`. Solo si no existe ninguno se responde 503.
   */
  async current(alerta: AlertaRow): Promise<EstadoRow> {
    const now = this.clock.now();
    const latest = alerta.estados[0] ?? null;
    const expected = this.expectedContent(alerta, now);
    if (
      latest &&
      latest.expiresAt.getTime() - now.getTime() > ESTADO_MARGEN_MS &&
      this.describes(latest, expected)
    ) {
      return latest;
    }

    const request = buildEstadoRequest(alerta.id, expected, now);
    try {
      const signed = await this.signing.sign(request);
      return await this.prisma.estadoAlerta.create({
        data: {
          id: randomUUID(),
          alertaId: alerta.id,
          secuencia: expected.secuencia,
          payloadCanonico: signed.bytes,
          hashPayload: signed.envelope.hash_payload,
          firma: signed.envelope.firma,
          keyId: signed.envelope.key_id,
          expiresAt: new Date(request.expires_at),
        },
      });
    } catch (error) {
      if (!(error instanceof SignerUnavailableError)) throw error;
      if (latest) {
        this.logger.warn(
          `Sin firmante: se sirve el último estado guardado de la alerta ${alerta.id}`,
        );
        return latest;
      }
      throw signerUnavailable();
    }
  }
}
