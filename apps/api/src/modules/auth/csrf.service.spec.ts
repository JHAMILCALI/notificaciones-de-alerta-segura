import type { AppConfig } from '../../config/env';
import { CsrfService } from './csrf.service';

const config = { csrfSecret: 'a'.repeat(48) } as AppConfig;
const otherSecretConfig = { csrfSecret: 'b'.repeat(48) } as AppConfig;

describe('CsrfService (signed double-submit ligado a la sesión)', () => {
  const csrf = new CsrfService(config);
  const sessionA = '11111111-1111-4111-8111-111111111111';
  const sessionB = '22222222-2222-4222-8222-222222222222';

  it('acepta un token válido cuando cabecera y cookie coinciden', () => {
    const token = csrf.issue(sessionA);
    expect(csrf.verify(token, token, sessionA)).toBe(true);
  });

  it('acepta un token anónimo en el contexto anónimo (login)', () => {
    const token = csrf.issue();
    expect(csrf.verify(token, token, undefined)).toBe(true);
  });

  it('rechaza token ausente (cabecera o cookie)', () => {
    const token = csrf.issue(sessionA);
    expect(csrf.verify(undefined, token, sessionA)).toBe(false);
    expect(csrf.verify(token, undefined, sessionA)).toBe(false);
    expect(csrf.verify('', '', sessionA)).toBe(false);
    expect(csrf.verify(undefined, undefined, sessionA)).toBe(false);
  });

  it('rechaza un token alterado', () => {
    const token = csrf.issue(sessionA);
    const [nonce, mac] = token.split('.') as [string, string];
    const flipped = `${nonce}.${mac.slice(0, -1)}${mac.endsWith('A') ? 'B' : 'A'}`;
    expect(csrf.verify(flipped, flipped, sessionA)).toBe(false);
    const otherNonce = `${nonce.slice(0, -1)}${nonce.endsWith('A') ? 'B' : 'A'}.${mac}`;
    expect(csrf.verify(otherNonce, otherNonce, sessionA)).toBe(false);
    expect(csrf.verify('sin-punto', 'sin-punto', sessionA)).toBe(false);
    expect(csrf.verify('a.b.c', 'a.b.c', sessionA)).toBe(false);
  });

  it('rechaza cuando cabecera y cookie son tokens válidos pero distintos', () => {
    const one = csrf.issue(sessionA);
    const two = csrf.issue(sessionA);
    expect(csrf.verify(one, two, sessionA)).toBe(false);
  });

  it('rechaza un token emitido para otra sesión', () => {
    const tokenOfB = csrf.issue(sessionB);
    expect(csrf.verify(tokenOfB, tokenOfB, sessionA)).toBe(false);
  });

  it('un token anónimo no vale con sesión y uno de sesión no vale como anónimo', () => {
    const anon = csrf.issue();
    const ofSession = csrf.issue(sessionA);
    expect(csrf.verify(anon, anon, sessionA)).toBe(false);
    expect(csrf.verify(ofSession, ofSession, undefined)).toBe(false);
  });

  it('un token firmado con otro secreto no vale', () => {
    const foreign = new CsrfService(otherSecretConfig).issue(sessionA);
    expect(csrf.verify(foreign, foreign, sessionA)).toBe(false);
  });

  it('no acepta valores que no son cadenas', () => {
    expect(csrf.verify(['x'], ['x'], sessionA)).toBe(false);
    expect(csrf.verify(123, 123, sessionA)).toBe(false);
  });
});
