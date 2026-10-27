import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import {
  AlertaIdParamSchema,
  AlertaListQuerySchema,
  CancelAlertaRequestSchema,
  type AlertaListResponse,
  type AlertaResponse,
} from '@alertasegura/shared';
import {
  CurrentUser,
  DeniedAction,
  Public,
  RequirePermissions,
  Validate,
  ValidParams,
  ValidQuery,
} from '../../common/decorators/metadata';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { AlertOwnershipGuard } from './alert-ownership.guard';
import { AlertsService } from './alerts.service';

/**
 * Lecturas públicas (el ciudadano no tiene sesión) y cancelación. No existe ninguna escritura pública: la
 * publicación está en `POST /drafts/:draftId/publish`, que exige sesión de emisor.
 */
@Controller('alerts')
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Public()
  @Validate({ query: AlertaListQuerySchema })
  @Get()
  list(@ValidQuery() query: unknown): Promise<AlertaListResponse> {
    const { limit } = query as { limit: number };
    return this.alerts.list(limit);
  }

  @Public()
  @Validate({ params: AlertaIdParamSchema })
  @Get(':alertaId')
  get(@ValidParams() params: unknown): Promise<AlertaResponse> {
    const { alertaId } = params as { alertaId: string };
    return this.alerts.getById(alertaId);
  }

  @RequirePermissions('alerts:cancel')
  @DeniedAction('CANCEL_DENIED')
  @Validate({ params: AlertaIdParamSchema, body: CancelAlertaRequestSchema })
  @UseGuards(AlertOwnershipGuard)
  @Post(':alertaId/cancel')
  cancel(
    @ValidParams() params: unknown,
    @CurrentUser() user: AuthenticatedUser,
    @Req() req: Request,
  ): Promise<AlertaResponse> {
    const { alertaId } = params as { alertaId: string };
    return this.alerts.cancel(alertaId, user, req);
  }
}
