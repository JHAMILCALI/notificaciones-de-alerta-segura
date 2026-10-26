import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import {
  CreateDraftRequestSchema,
  DraftIdParamSchema,
  type CreateDraftRequest,
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
import { ApiException } from '../../common/http/api-exception';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { AuditService } from '../audit/audit.service';
import { DraftOwnershipGuard } from './draft-ownership.guard';
import { DraftsService } from './drafts.service';

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
   * Transitorio (entrega 1 de la semana 2): superados rate limiting, sesión, CSRF, validación,
   * RBAC y propiedad, todavía no hay firmante conectado; no se publica ni se simula nada.
   * La entrega 3 lo reemplaza por la publicación atómica con firma.
   */
  @RequirePermissions('alerts:publish')
  @DeniedAction('PUBLICATION_DENIED')
  @Validate({ params: DraftIdParamSchema })
  @UseGuards(DraftOwnershipGuard)
  @Post(':draftId/publish')
  publish(): never {
    throw new ApiException(
      501,
      'SIGNER_UNAVAILABLE',
      'La publicación firmada aún no está conectada al firmante',
    );
  }
}
