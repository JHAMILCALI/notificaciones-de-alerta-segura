import type { AlertaPublicada, SignedEnvelope } from '@alertasegura/shared';
import type { Prisma } from '@alertasegura/database';
import { toIsoSeconds } from '../../common/clock/clock';

export const alertaInclude = {
  evento: true,
  // El último estado guardado: mayor secuencia y, a igual secuencia, el más reciente.
  estados: {
    orderBy: [{ secuencia: 'desc' }, { createdAt: 'desc' }],
    take: 1,
  },
} satisfies Prisma.AlertaPublicadaInclude;

export type AlertaRow = Prisma.AlertaPublicadaGetPayload<{
  include: typeof alertaInclude;
}>;
export type EventoRow = NonNullable<AlertaRow['evento']>;
export type EstadoRow = AlertaRow['estados'][number];

const b64 = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');

/** Sobre firmado tal como se guardó: los bytes no se reconstruyen. */
export function alertaEnvelope(row: AlertaRow): SignedEnvelope {
  return {
    payload_canonico: b64(row.payloadCanonico),
    hash_payload: row.hashPayload,
    firma: row.firma,
    key_id: row.keyId,
  };
}

export function eventoEnvelope(row: EventoRow): SignedEnvelope {
  return {
    payload_canonico: b64(row.payloadCanonico),
    hash_payload: row.hashEvento,
    firma: row.firma,
    key_id: row.keyId,
  };
}

export function estadoEnvelope(row: EstadoRow): SignedEnvelope {
  return {
    payload_canonico: b64(row.payloadCanonico),
    hash_payload: row.hashPayload,
    firma: row.firma,
    key_id: row.keyId,
  };
}

export function toAlertaPublicada(
  row: AlertaRow,
  estado: EstadoRow,
): AlertaPublicada {
  return {
    id: row.id,
    emisorId: row.emisorId,
    publishedAt: row.publishedAt.toISOString(),
    // Copia NO verificada para listar; la PWA solo confía en lo que verifica sobre `alerta`.
    resumen: {
      tipo: row.tipo,
      zona: { departamento: row.departamento, municipio: row.municipio },
      severidad: row.severidad,
      mensaje: row.mensaje,
      emitida_en: toIsoSeconds(row.emitidaEn),
      expira_en: toIsoSeconds(row.expiraEn),
    },
    alerta: alertaEnvelope(row),
    eventos: row.evento ? [eventoEnvelope(row.evento)] : [],
    estado: estadoEnvelope(estado),
  };
}
