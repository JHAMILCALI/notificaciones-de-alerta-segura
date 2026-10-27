import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import type { PrismaService } from '../../database/prisma.service';
import { DeniedAction } from '../../common/decorators/metadata';
import type { AuditService } from '../audit/audit.service';
import { DraftOwnershipGuard } from './draft-ownership.guard';

const OWNER = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const DRAFT = '33333333-3333-4333-8333-333333333333';

class Routes {
  plain(): void {}
  @DeniedAction('PUBLICATION_DENIED') publish(): void {}
}

function setup(draft: { id: string; ownerId: string } | null) {
  const findUnique = jest.fn().mockResolvedValue(draft);
  const record = jest.fn().mockResolvedValue(undefined);
  const guard = new DraftOwnershipGuard(
    { draft: { findUnique } } as unknown as PrismaService,
    { record } as unknown as AuditService,
    new Reflector(),
  );
  const context = (
    userId: string | undefined,
    handler: keyof Routes = 'plain',
  ): ExecutionContext => {
    const req = {
      method: 'POST',
      originalUrl: `/api/v1/drafts/${DRAFT}/publish`,
      auth: userId
        ? {
            sessionId: 's',
            user: { id: userId, email: 'e', displayName: 'n', role: 'ISSUER' },
          }
        : undefined,
      validated: { params: { draftId: DRAFT } },
    } as unknown as Request;
    return {
      switchToHttp: () => ({ getRequest: () => req }),
      getHandler: () =>
        (Routes.prototype as Record<keyof Routes, () => void>)[handler],
      getClass: () => Routes,
    } as unknown as ExecutionContext;
  };
  return { guard, context, findUnique, record };
}

describe('DraftOwnershipGuard (autorización por propiedad)', () => {
  it('permite al propietario', async () => {
    const { guard, context, record } = setup({ id: DRAFT, ownerId: OWNER });
    await expect(guard.canActivate(context(OWNER))).resolves.toBe(true);
    expect(record).not.toHaveBeenCalled();
  });

  it('deniega con 403 a otro emisor y lo audita con el actor y el recurso', async () => {
    const { guard, context, record } = setup({ id: DRAFT, ownerId: OWNER });
    await expect(guard.canActivate(context(OTHER))).rejects.toMatchObject({
      code: 'FORBIDDEN',
      status: 403,
    });
    expect(record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'ACCESS_DENIED',
        outcome: 'DENIED',
        actorId: OTHER,
        targetType: 'draft',
        targetId: DRAFT,
      }),
    );
  });

  it('usa la acción de auditoría de la ruta (PUBLICATION_DENIED en publicar)', async () => {
    const { guard, context, record } = setup({ id: DRAFT, ownerId: OWNER });
    await expect(
      guard.canActivate(context(OTHER, 'publish')),
    ).rejects.toBeDefined();
    expect(record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'PUBLICATION_DENIED' }),
    );
  });

  it('404 NOT_FOUND si el borrador no existe', async () => {
    const { guard, context } = setup(null);
    await expect(guard.canActivate(context(OWNER))).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
  });

  it('sin usuario o sin :draftId validado se deniega y no consulta la base', async () => {
    const { guard, context, findUnique } = setup({ id: DRAFT, ownerId: OWNER });
    await expect(guard.canActivate(context(undefined))).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
    expect(findUnique).not.toHaveBeenCalled();
  });
});
