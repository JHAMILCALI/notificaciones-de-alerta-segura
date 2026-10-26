import { Controller, Get, Logger, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  ROLES,
  type Permission,
  type Role,
} from '@alertasegura/shared';
import type { AuditService } from '../../modules/audit/audit.service';
import {
  AnyRole,
  DeniedAction,
  Public,
  RequirePermissions,
} from '../decorators/metadata';
import { ApiException } from '../http/api-exception';
import { PermissionsGuard } from './permissions.guard';

@Controller('x')
class Dummy {
  @RequirePermissions('users:read') usersRead(): void {}
  @RequirePermissions('drafts:create') draftsCreate(): void {}
  @RequirePermissions('drafts:read-own') draftsRead(): void {}
  @RequirePermissions('alerts:publish')
  @DeniedAction('PUBLICATION_DENIED')
  publish(): void {}
  @RequirePermissions('alerts:cancel')
  @DeniedAction('CANCEL_DENIED')
  cancel(): void {}
  @RequirePermissions('audit:read') auditRead(): void {}
  @RequirePermissions('drafts:create', 'alerts:publish') both(): void {}
  @AnyRole() any(): void {}
  @Public() open(): void {}
  @Get() undeclared(): void {}
}

const handlerFor: Record<Permission, keyof Dummy> = {
  'users:read': 'usersRead',
  'drafts:create': 'draftsCreate',
  'drafts:read-own': 'draftsRead',
  'alerts:publish': 'publish',
  'alerts:cancel': 'cancel',
  'audit:read': 'auditRead',
};

function setup() {
  const record = jest.fn().mockResolvedValue(undefined);
  const guard = new PermissionsGuard(new Reflector(), {
    record,
  } as unknown as AuditService);
  const context = (method: keyof Dummy, role?: Role): ExecutionContext => {
    const req = {
      method: 'POST',
      originalUrl: '/api/v1/x',
      auth: role
        ? {
            sessionId: 's',
            user: { id: 'u1', email: 'e', displayName: 'n', role },
          }
        : undefined,
    } as unknown as Request;
    return {
      switchToHttp: () => ({ getRequest: () => req }),
      getHandler: () =>
        (Dummy.prototype as Record<keyof Dummy, () => void>)[method],
      getClass: () => Dummy,
    } as unknown as ExecutionContext;
  };
  return { guard, record, context };
}

describe('RBAC: PermissionsGuard contra ROLE_PERMISSIONS', () => {
  beforeAll(() => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterAll(() => jest.restoreAllMocks());

  describe.each(ROLES)('rol %s', (role) => {
    it.each(PERMISSIONS)('permiso %s', async (permission) => {
      const { guard, context, record } = setup();
      const expected = ROLE_PERMISSIONS[role].includes(permission);
      const result = guard.canActivate(context(handlerFor[permission], role));
      if (expected) {
        await expect(result).resolves.toBe(true);
        expect(record).not.toHaveBeenCalled();
      } else {
        await expect(result).rejects.toMatchObject({ code: 'FORBIDDEN' });
        expect(record).toHaveBeenCalledTimes(1);
      }
    });
  });

  it('matriz explícita: solo ISSUER puede publicar; ADMIN y AUDITOR no', async () => {
    const { guard, context } = setup();
    await expect(guard.canActivate(context('publish', 'ISSUER'))).resolves.toBe(
      true,
    );
    await expect(
      guard.canActivate(context('publish', 'ADMIN')),
    ).rejects.toBeInstanceOf(ApiException);
    await expect(
      guard.canActivate(context('publish', 'AUDITOR')),
    ).rejects.toBeInstanceOf(ApiException);
  });

  it('una denegación de publicación se audita como PUBLICATION_DENIED', async () => {
    const { guard, context, record } = setup();
    await expect(
      guard.canActivate(context('publish', 'AUDITOR')),
    ).rejects.toBeDefined();
    expect(record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'PUBLICATION_DENIED',
        outcome: 'DENIED',
        actorId: 'u1',
      }),
    );
  });

  it('con varios permisos exige todos', async () => {
    const { guard, context } = setup();
    await expect(guard.canActivate(context('both', 'ISSUER'))).resolves.toBe(
      true,
    );
    await expect(
      guard.canActivate(context('both', 'ADMIN')),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('@AnyRole permite a cualquier rol autenticado y @Public pasa sin sesión', async () => {
    const { guard, context } = setup();
    for (const role of ROLES) {
      await expect(guard.canActivate(context('any', role))).resolves.toBe(true);
    }
    await expect(guard.canActivate(context('open'))).resolves.toBe(true);
  });

  it('una ruta sin política declarada se deniega por defecto', async () => {
    const { guard, context, record } = setup();
    await expect(
      guard.canActivate(context('undeclared', 'ADMIN')),
    ).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
    expect(record).toHaveBeenCalledTimes(1);
  });

  it('sin usuario en la petición se deniega', async () => {
    const { guard, context } = setup();
    await expect(guard.canActivate(context('usersRead'))).rejects.toMatchObject(
      { code: 'FORBIDDEN' },
    );
  });
});
