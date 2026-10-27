import { ARGON2_OPTIONS, hashPassword } from '@alertasegura/database';
import { PasswordService } from './password.service';

describe('PasswordService (Argon2id)', () => {
  const service = new PasswordService();
  const password = 'contraseña-de-prueba-Ab12!';

  beforeAll(async () => {
    await service.onModuleInit();
  });

  it('genera hashes Argon2id con los parámetros OWASP (m=19456, t=2, p=1)', async () => {
    const hash = await service.hash(password);
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(hash).toContain('m=19456,t=2,p=1');
    expect(ARGON2_OPTIONS.memoryCost).toBe(19456);
    expect(ARGON2_OPTIONS.timeCost).toBe(2);
    expect(ARGON2_OPTIONS.parallelism).toBe(1);
  });

  it('usa sal distinta en cada hash', async () => {
    const [a, b] = await Promise.all([
      service.hash(password),
      service.hash(password),
    ]);
    expect(a).not.toBe(b);
  });

  it('acepta la contraseña correcta y rechaza la incorrecta', async () => {
    const hash = await service.hash(password);
    await expect(service.verify(hash, password)).resolves.toBe(true);
    await expect(service.verify(hash, password + 'x')).resolves.toBe(false);
    await expect(service.verify(hash, '')).resolves.toBe(false);
  });

  it('cuenta inexistente (sin hash): verifica contra el señuelo y devuelve false', async () => {
    await expect(service.verify(null, password)).resolves.toBe(false);
  });

  it('un hash mal formado devuelve false en lugar de lanzar', async () => {
    await expect(service.verify('no-es-un-hash', password)).resolves.toBe(
      false,
    );
  });

  it('el tiempo de verificar una cuenta inexistente es comparable al de una existente', async () => {
    const real = await hashPassword(password);
    const time = async (hash: string | null): Promise<number> => {
      const start = process.hrtime.bigint();
      await service.verify(hash, 'otra-contraseña-cualquiera');
      return Number(process.hrtime.bigint() - start) / 1e6;
    };
    await time(real); // calentamiento
    const known = ((await time(real)) + (await time(real))) / 2;
    const unknown = ((await time(null)) + (await time(null))) / 2;
    // Ambos ejecutan Argon2id completo: la razón debe estar lejos de "instantáneo" (< 0.2x).
    expect(unknown / known).toBeGreaterThan(0.2);
    expect(unknown / known).toBeLessThan(5);
  });
});
