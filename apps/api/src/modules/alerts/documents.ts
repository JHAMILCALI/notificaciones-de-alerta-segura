import {
  DOCUMENT_SCHEMA_VERSION,
  ESTADO_FRESCURA_MAX_SEGUNDOS,
  type EstadoAlertaValor,
  type SignRequest,
} from '@alertasegura/shared';
import { floorToSecond, toIsoSeconds } from '../../common/clock/clock';

type RequestOf<T extends SignRequest['tipo_doc']> = Extract<
  SignRequest,
  { tipo_doc: T }
>;

export interface DraftForSigning {
  ownerId: string;
  tipo: RequestOf<'ALERTA'>['tipo'];
  departamento: RequestOf<'ALERTA'>['zona']['departamento'];
  municipio: string | null;
  severidad: RequestOf<'ALERTA'>['severidad'];
  mensaje: string;
  vigenciaHoras: number;
}

/** D-4: emitida_en = ahora y expira_en = ahora + vigenciaHoras, en UTC con segundos. */
export function buildAlertaRequest(
  draft: DraftForSigning,
  alertaId: string,
  now: Date,
): RequestOf<'ALERTA'> {
  const emitida = floorToSecond(now);
  const expira = new Date(emitida.getTime() + draft.vigenciaHoras * 3_600_000);
  return {
    tipo_doc: 'ALERTA',
    version: DOCUMENT_SCHEMA_VERSION,
    alerta_id: alertaId,
    emisor_id: draft.ownerId,
    tipo: draft.tipo,
    zona: { departamento: draft.departamento, municipio: draft.municipio },
    severidad: draft.severidad,
    mensaje: draft.mensaje,
    emitida_en: toIsoSeconds(emitida),
    expira_en: toIsoSeconds(expira),
  };
}

export interface EstadoContent {
  estado: EstadoAlertaValor;
  /** 0 sin eventos; +1 por cada evento aceptado. */
  secuencia: number;
  /** SHA-256 del último EVENTO; null si no hay eventos. */
  ultimoEventoHash: string | null;
}

export function buildEstadoRequest(
  alertaId: string,
  content: EstadoContent,
  now: Date,
): RequestOf<'ESTADO'> {
  const issued = floorToSecond(now);
  const expires = new Date(
    issued.getTime() + ESTADO_FRESCURA_MAX_SEGUNDOS * 1000,
  );
  return {
    tipo_doc: 'ESTADO',
    version: DOCUMENT_SCHEMA_VERSION,
    alerta_id: alertaId,
    secuencia: content.secuencia,
    ultimo_evento_hash: content.ultimoEventoHash,
    estado: content.estado,
    issued_at: toIsoSeconds(issued),
    expires_at: toIsoSeconds(expires),
  };
}

export function buildCancelacionRequest(input: {
  eventoId: string;
  alertaId: string;
  hashAlerta: string;
  emisorId: string;
  now: Date;
}): RequestOf<'EVENTO'> {
  return {
    tipo_doc: 'EVENTO',
    version: DOCUMENT_SCHEMA_VERSION,
    evento_id: input.eventoId,
    alerta_id: input.alertaId,
    hash_alerta: input.hashAlerta,
    emisor_id: input.emisorId,
    accion: 'CANCELACION',
    emitida_en: toIsoSeconds(floorToSecond(input.now)),
  };
}
