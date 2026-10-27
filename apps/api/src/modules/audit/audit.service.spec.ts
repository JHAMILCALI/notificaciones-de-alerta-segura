import type { PrismaService } from '../../database/prisma.service';
import { AuditService, sanitizeMetadata } from './audit.service';

describe('sanitizeMetadata', () => {
  it('elimina claves que podrían contener credenciales, a cualquier profundidad', () => {
    const out = sanitizeMetadata({
      email: 'a@b.co',
      password: 'secreto',
      newPassword: 'secreto',
      token: 't',
      csrfToken: 't',
      cookie: 'c',
      Authorization: 'Bearer x',
      passwordHash: 'h',
      nested: {
        sessionToken: 't',
        ok: 1,
        deeper: [{ secret: 's', fine: true }],
      },
    }) as Record<string, unknown>;
    expect(out).toEqual({
      email: 'a@b.co',
      nested: { ok: 1, deeper: [{ fine: true }] },
    });
    expect(JSON.stringify(out)).not.toContain('secreto');
  });

  it('acota cadenas largas y profundidad', () => {
    const long = sanitizeMetadata({ v: 'x'.repeat(10_000) }) as { v: string };
    expect(long.v.length).toBe(500);
    const deep = sanitizeMetadata({ a: { b: { c: { d: { e: 1 } } } } });
    expect(JSON.stringify(deep)).toContain('[truncado]');
  });
});

describe('AuditService.record', () => {
  it('no lanza si la escritura falla (la petición no se cae) y deja constancia en el log', async () => {
    const create = jest.fn().mockRejectedValue(new Error('db caída'));
    const service = new AuditService({
      auditLog: { create },
    } as unknown as PrismaService);
    const errorSpy = jest
      .spyOn(
        (service as unknown as { logger: { error: (m: string) => void } })
          .logger,
        'error',
      )
      .mockImplementation(() => undefined);
    await expect(
      service.record({
        action: 'AUTH_LOGOUT',
        outcome: 'SUCCESS',
        actorId: 'u1',
      }),
    ).resolves.toBeUndefined();
    expect(create).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('FALLO DE AUDITORIA'),
    );
  });

  it('guarda el metadata ya saneado', async () => {
    const create = jest.fn().mockResolvedValue({});
    const service = new AuditService({
      auditLog: { create },
    } as unknown as PrismaService);
    await service.record({
      action: 'AUTH_LOGIN_FAILED',
      outcome: 'FAILURE',
      metadata: { email: 'a@b.co', password: 'no-debe-guardarse' },
    });
    const data = (create.mock.calls[0] as [{ data: { metadata: unknown } }])[0]
      .data;
    expect(JSON.stringify(data.metadata)).not.toContain('no-debe-guardarse');
  });
});
