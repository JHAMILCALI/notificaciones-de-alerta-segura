import { Injectable, type OnModuleInit } from '@nestjs/common';
import { hashPassword, verifyPassword } from '@alertasegura/database';
import { randomToken } from '../../common/crypto/tokens';

@Injectable()
export class PasswordService implements OnModuleInit {
  /** Hash Argon2id de una contraseña aleatoria que nadie conoce: sirve de señuelo. */
  private decoyHash = '';

  async onModuleInit(): Promise<void> {
    this.decoyHash = await hashPassword(randomToken(24));
  }

  hash(password: string): Promise<string> {
    return hashPassword(password);
  }

  /**
   * Verifica `password` contra `storedHash`. Si no hay hash (cuenta inexistente) se verifica
   * contra el señuelo para que el tiempo de respuesta no revele si el correo existe.
   * Devuelve siempre false cuando no hay hash real.
   */
  async verify(storedHash: string | null, password: string): Promise<boolean> {
    if (storedHash === null) {
      await verifyPassword(this.decoyHash, password);
      return false;
    }
    return verifyPassword(storedHash, password);
  }
}
