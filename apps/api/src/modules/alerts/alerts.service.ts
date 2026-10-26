import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger } from '@nestjs/common';
import type { Request } from 'express';
import { Prisma } from '@alertasegura/database';
import {
  AlertaDocumentoSchema,
  type AlertaListResponse,
  type AlertaResponse,
} from '@alertasegura/shared';
import { CLOCK, type Clock } from '../../common/clock/clock';
import {
  ApiException,
  conflict,
  forbidden,
  notFound,
  signerUnavailable,
} from '../../common/http/api-exception';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { PrismaService } from '../../database/prisma.service';
import { AuditService } from '../audit/audit.service';
import { SignerUnavailableError } from '../signer/signer.client';
import { AlertStateService } from './alert-state.service';
import {
  alertaInclude,
  toAlertaPublicada,
  type AlertaRow,
  type EstadoRow,
} from './alerts.mapper';
import {
  buildAlertaRequest,
  buildCancelacionRequest,
  buildEstadoRequest,
} from './documents';
import { PublishQuotaService } from './publish-quota.service';
import { SigningService } from './signing.service';

/** Las regeneraciones de estado de un listado se piden al firmante en tandas, no todas a la vez. */
const REFRESH_CONCURRENCY = 5;

class AlreadyPublishedError extends Error {}

const isUniqueViolation = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError &&
  error.code === 'P2002';

const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : 'error desconocido';

@Injectable()
export class AlertsService {
  private readonly logger = new Logger(AlertsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly signing: SigningService,
    private readonly states: AlertStateService,
    private readonly quota: PublishQuotaService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Publicación atómica (api-contract-semana2.md): el firmante firma la ALERTA y el ESTADO inicial FUERA de la
   * transacción; después, en una sola transacción, se guardan los bytes exactos, el borrador pasa a PUBLISHED
   * y se audita. Si el firmante falla no se escribe nada (salvo la auditoría PUBLICATION_FAILED).
   */
  async publish(
    draftId: string,
    user: AuthenticatedUser,
    req: Request,
  ): Promise<AlertaResponse> {
    const draft = await this.prisma.draft.findUnique({
      where: { id: draftId },
    });
    if (!draft) throw notFound();
    if (draft.status === 'PUBLISHED' || draft.alertaId) {
      throw conflict('El borrador ya está publicado');
    }

    const now = this.clock.now();
    const alertaId = randomUUID();
    const alertaRequest = buildAlertaRequest(draft, alertaId, now);
    const estadoRequest = buildEstadoRequest(
      alertaId,
      { estado: 'VIGENTE', secuencia: 0, ultimoEventoHash: null },
      now,
    );

    let signedAlerta;
    let signedEstado;
    try {
      signedAlerta = await this.signing.sign(alertaRequest);
      signedEstado = await this.signing.sign(estadoRequest);
    } catch (error) {
      if (!(error instanceof SignerUnavailableError)) throw error;
      await this.audit.record({
        action: 'PUBLICATION_FAILED',
        outcome: 'FAILURE',
        actorId: user.id,
        targetType: 'draft',
        targetId: draft.id,
        req,
        metadata: { reason: 'signer_unavailable' },
      });
      throw signerUnavailable();
    }

    // Lo que quedó firmado es la fuente de verdad: el resumen sale del documento, no del borrador.
    const doc = AlertaDocumentoSchema.parse(signedAlerta.payload);
    try {
      await this.prisma.$transaction(async (tx) => {
        // Cuota definitiva: bajo un bloqueo por emisor, así dos publicaciones simultáneas no la rebasan.
        await this.quota.lockEmisor(tx, doc.emisor_id);
        await this.quota.enforce(tx, doc.emisor_id, req);
        await tx.alertaPublicada.create({
          data: {
            id: doc.alerta_id,
            emisorId: doc.emisor_id,
            draftId: draft.id,
            payloadCanonico: signedAlerta.bytes,
            hashPayload: signedAlerta.envelope.hash_payload,
            firma: signedAlerta.envelope.firma,
            keyId: signedAlerta.envelope.key_id,
            tipo: doc.tipo,
            departamento: doc.zona.departamento,
            municipio: doc.zona.municipio,
            severidad: doc.severidad,
            mensaje: doc.mensaje,
            emitidaEn: new Date(doc.emitida_en),
            expiraEn: new Date(doc.expira_en),
          },
        });
        await tx.estadoAlerta.create({
          data: {
            id: randomUUID(),
            alertaId: doc.alerta_id,
            secuencia: 0,
            payloadCanonico: signedEstado.bytes,
            hashPayload: signedEstado.envelope.hash_payload,
            firma: signedEstado.envelope.firma,
            keyId: signedEstado.envelope.key_id,
            expiresAt: new Date(estadoRequest.expires_at),
          },
        });
        const marked = await tx.draft.updateMany({
          where: { id: draft.id, status: 'DRAFT' },
          data: { status: 'PUBLISHED', alertaId: doc.alerta_id },
        });
        if (marked.count !== 1) throw new AlreadyPublishedError();
        await this.audit.recordInTransaction(tx, {
          action: 'ALERT_PUBLISHED',
          outcome: 'SUCCESS',
          actorId: user.id,
          targetType: 'alerta',
          targetId: doc.alerta_id,
          req,
          metadata: {
            draftId: draft.id,
            keyId: signedAlerta.envelope.key_id,
            alertaSha256: signedAlerta.envelope.hash_payload,
            tipo: doc.tipo,
            departamento: doc.zona.departamento,
            severidad: doc.severidad,
          },
        });
      });
    } catch (error) {
      if (error instanceof ApiException) throw error; // cuota excedida (429): nada que revertir
      // Dos publicaciones simultáneas del mismo borrador: gana una y la otra recibe 409.
      if (error instanceof AlreadyPublishedError || isUniqueViolation(error)) {
        throw conflict('El borrador ya está publicado');
      }
      this.logger.error(
        `Publicación revertida del borrador ${draft.id}: ${messageOf(error)}`,
      );
      await this.audit.record({
        action: 'PUBLICATION_FAILED',
        outcome: 'FAILURE',
        actorId: user.id,
        targetType: 'draft',
        targetId: draft.id,
        req,
        metadata: { reason: 'persist_failed' },
      });
      throw error;
    }

    return this.getById(doc.alerta_id);
  }

  /**
   * Cancelación (P02c). El dueño ya se comprobó en AlertOwnershipGuard; aquí se repite como defensa en
   * profundidad. El EVENTO y el nuevo ESTADO (CANCELADA, secuencia 1) se firman fuera de la transacción.
   */
  async cancel(
    alertaId: string,
    user: AuthenticatedUser,
    req: Request,
  ): Promise<AlertaResponse> {
    const alerta = await this.prisma.alertaPublicada.findUnique({
      where: { id: alertaId },
      include: alertaInclude,
    });
    if (!alerta) throw notFound();
    if (alerta.emisorId !== user.id) throw forbidden();
    if (alerta.evento) throw conflict('La alerta ya fue cancelada');

    const now = this.clock.now();
    const eventoRequest = buildCancelacionRequest({
      eventoId: randomUUID(),
      alertaId: alerta.id,
      hashAlerta: alerta.hashPayload,
      emisorId: user.id,
      now,
    });

    let signedEvento;
    let signedEstado;
    let estadoExpires: string;
    try {
      signedEvento = await this.signing.sign(eventoRequest);
      const estadoRequest = buildEstadoRequest(
        alerta.id,
        {
          estado: 'CANCELADA',
          secuencia: 1,
          ultimoEventoHash: signedEvento.envelope.hash_payload,
        },
        now,
      );
      estadoExpires = estadoRequest.expires_at;
      signedEstado = await this.signing.sign(estadoRequest);
    } catch (error) {
      if (!(error instanceof SignerUnavailableError)) throw error;
      await this.audit.record({
        action: 'CANCEL_FAILED',
        outcome: 'FAILURE',
        actorId: user.id,
        targetType: 'alerta',
        targetId: alerta.id,
        req,
        metadata: { reason: 'signer_unavailable' },
      });
      throw signerUnavailable();
    }

    try {
      await this.prisma.$transaction(async (tx) => {
        await tx.eventoAlerta.create({
          data: {
            id: eventoRequest.evento_id,
            alertaId: alerta.id,
            payloadCanonico: signedEvento.bytes,
            hashEvento: signedEvento.envelope.hash_payload,
            hashAlerta: alerta.hashPayload,
            firma: signedEvento.envelope.firma,
            keyId: signedEvento.envelope.key_id,
          },
        });
        await tx.estadoAlerta.create({
          data: {
            id: randomUUID(),
            alertaId: alerta.id,
            secuencia: 1,
            payloadCanonico: signedEstado.bytes,
            hashPayload: signedEstado.envelope.hash_payload,
            firma: signedEstado.envelope.firma,
            keyId: signedEstado.envelope.key_id,
            expiresAt: new Date(estadoExpires),
          },
        });
        await this.audit.recordInTransaction(tx, {
          action: 'ALERT_CANCELLED',
          outcome: 'SUCCESS',
          actorId: user.id,
          targetType: 'alerta',
          targetId: alerta.id,
          req,
          metadata: {
            eventoId: eventoRequest.evento_id,
            eventoSha256: signedEvento.envelope.hash_payload,
            keyId: signedEvento.envelope.key_id,
          },
        });
      });
    } catch (error) {
      // Una sola cancelación por alerta (alertaId único): la segunda simultánea recibe 409.
      if (isUniqueViolation(error)) {
        throw conflict('La alerta ya fue cancelada');
      }
      this.logger.error(
        `Cancelación revertida de la alerta ${alerta.id}: ${messageOf(error)}`,
      );
      await this.audit.record({
        action: 'CANCEL_FAILED',
        outcome: 'FAILURE',
        actorId: user.id,
        targetType: 'alerta',
        targetId: alerta.id,
        req,
        metadata: { reason: 'persist_failed' },
      });
      throw error;
    }

    return this.getById(alerta.id);
  }

  async getById(alertaId: string): Promise<AlertaResponse> {
    const row = await this.prisma.alertaPublicada.findUnique({
      where: { id: alertaId },
      include: alertaInclude,
    });
    if (!row) throw notFound();
    return { alerta: toAlertaPublicada(row, await this.states.current(row)) };
  }

  async list(limit: number): Promise<AlertaListResponse> {
    const rows = await this.prisma.alertaPublicada.findMany({
      orderBy: [{ publishedAt: 'desc' }, { id: 'desc' }],
      take: limit,
      include: alertaInclude,
    });
    const estados: EstadoRow[] = [];
    for (let i = 0; i < rows.length; i += REFRESH_CONCURRENCY) {
      const batch: AlertaRow[] = rows.slice(i, i + REFRESH_CONCURRENCY);
      estados.push(
        ...(await Promise.all(batch.map((row) => this.states.current(row)))),
      );
    }
    return {
      alertas: rows.map((row, i) => toAlertaPublicada(row, estados[i])),
    };
  }
}
