import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import {
  CreateDraftRequestSchema,
  DraftIdParamSchema,
  type CreateDraftRequest,
  type AlertaResponse,
  type DraftListResponse,
  type DraftResponse,
} from '@alertasegura/shared';
import {
  CurrentUser,
  DeniedAction,
  RequirePermissions,
  Validate,
  ValidBody,
  ValidParams,
} from '../../common/decorators/metadata';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { AlertsService } from '../alerts/alerts.service';
import { PublishQuotaGuard } from '../alerts/publish-quota.guard';
import { AuditService } from '../audit/audit.service';
import { DraftOwnershipGuard } from './draft-ownership.guard';
import { DraftsService } from './drafts.service';

@Controller('drafts')
export class DraftsController {
  constructor(
    private readonly drafts: DraftsService,
    private readonly audit: AuditService,
    private readonly alerts: AlertsService,
  ) {}

  @RequirePermissions('drafts:create')
  @Validate({ body: CreateDraftRequestSchema })
  @Post()
  async create(
    @ValidBody() body: unknown,
    @CurrentUser() user: AuthenticatedUser,
    @Req() req: Request,
  ): Promise<DraftResponse> {
    const draft = await this.drafts.create(body as CreateDraftRequest, user.id);
    await this.audit.record({
      action: 'DRAFT_CREATED',
      outcome: 'SUCCESS',
      actorId: user.id,
      targetType: 'draft',
      targetId: draft.id,
      req,
      metadata: {
        tipo: draft.tipo,
        departamento: draft.zona.departamento,
        severidad: draft.severidad,
      },
    });
    return { draft };
  }

  @RequirePermissions('drafts:read-own')
  @Get()
  async list(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<DraftListResponse> {
    return { drafts: await this.drafts.listOwn(user.id) };
  }

  @RequirePermissions('drafts:read-own')
  @Validate({ params: DraftIdParamSchema })
  @UseGuards(DraftOwnershipGuard)
  @Get(':draftId')
  async get(@ValidParams() params: unknown): Promise<DraftResponse> {
    const { draftId } = params as { draftId: string };
    return { draft: await this.drafts.getById(draftId) };
  }

  /**
   * Publicación atómica y firmada (api-contract-semana2.md). Los controles anteriores (rate limiting, sesión,
   * CSRF, validación, RBAC y propiedad) ya se superaron y la cuota se comprueba antes de firmar; la firma, la transacción y la auditoría están en
   * AlertsService.
   */
  @RequirePermissions('alerts:publish')
  @DeniedAction('PUBLICATION_DENIED')
  @Validate({ params: DraftIdParamSchema })
  @UseGuards(DraftOwnershipGuard, PublishQuotaGuard)
  @Post(':draftId/publish')
  publish(
    @ValidParams() params: unknown,
    @CurrentUser() user: AuthenticatedUser,
    @Req() req: Request,
  ): Promise<AlertaResponse> {
    const { draftId } = params as { draftId: string };
    return this.alerts.publish(draftId, user, req);
  }
}
