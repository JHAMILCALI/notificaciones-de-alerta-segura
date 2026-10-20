import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import type { z } from 'zod';
import {
  CreateDraftRequestSchema,
  DraftIdParamSchema,
  DraftListResponseSchema,
  DraftResponseSchema,
  type CreateDraftRequest,
} from '@alertasegura/shared';
import {
  CurrentUser,
  DeniedAction,
  RequirePermissions,
  Validate,
  ValidBody,
  ValidParams,
} from '../../common/decorators/metadata';
import { ApiException } from '../../common/http/api-exception';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { AuditService } from '../audit/audit.service';
import { DraftOwnershipGuard } from './draft-ownership.guard';
import { DraftsService } from './drafts.service';

// shared exporta los esquemas pero no estos dos tipos (cambio de contrato menor solicitado).
type DraftResponse = z.infer<typeof DraftResponseSchema>;
type DraftListResponse = z.infer<typeof DraftListResponseSchema>;

@Controller('drafts')
export class DraftsController {
  constructor(
    private readonly drafts: DraftsService,
    private readonly audit: AuditService,
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
      metadata: { severity: draft.severity },
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
   * Semana 1: superados rate limiting, sesión, CSRF, validación, RBAC y propiedad, se deja
   * constancia de la autorización y se responde 501. La firma aislada es de la semana 2;
   * no se simula nada.
   */
  @RequirePermissions('alerts:publish')
  @DeniedAction('PUBLICATION_DENIED')
  @Validate({ params: DraftIdParamSchema })
  @UseGuards(DraftOwnershipGuard)
  @Post(':draftId/publish')
  async publish(
    @ValidParams() params: unknown,
    @CurrentUser() user: AuthenticatedUser,
    @Req() req: Request,
  ): Promise<never> {
    const { draftId } = params as { draftId: string };
    await this.audit.record({
      action: 'PUBLICATION_AUTHORIZED',
      outcome: 'SUCCESS',
      actorId: user.id,
      targetType: 'draft',
      targetId: draftId,
      req,
      metadata: {
        signed: false,
        note: 'publicación firmada pendiente (semana 2)',
      },
    });
    throw new ApiException(
      501,
      'PUBLICATION_NOT_IMPLEMENTED',
      'La publicación firmada aún no está implementada',
    );
  }
}
