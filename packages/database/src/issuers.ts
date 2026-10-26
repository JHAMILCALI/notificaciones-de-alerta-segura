import { Prisma, Role } from './generated/client';
import type { PrismaClient } from './generated/client';
import { hashPassword } from './password';

/** Mismos límites que ProvisionIssuerRequestSchema (packages/shared); database no depende de shared. */
export const ISSUER_PASSWORD_MIN_LENGTH = 12;
export const ISSUER_PASSWORD_MAX_LENGTH = 128;
const DISPLAY_NAME_MIN = 2;
const DISPLAY_NAME_MAX = 100;
const EMAIL_MAX = 254;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface AddIssuerInput {
  email: string;
  displayName: string;
  password: string;
}

export interface AddedIssuer {
  id: string;
  email: string;
  displayName: string;
}

/** Entrada inválida o correo ya registrado; el mensaje es seguro para mostrarlo en la terminal. */
export class AddIssuerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AddIssuerError';
  }
}

/**
 * Alta de un ISSUER desde el comando de laboratorio (D-1): el endpoint HTTP se retiró. Crea la
 * cuenta y deja el registro `ISSUER_PROVISIONED` en la misma transacción, con `actorId = null` y
 * `metadata.actor = "lab-script"`. Debe recibir un cliente conectado con el rol propietario.
 */
export async function addIssuer(prisma: PrismaClient, input: AddIssuerInput): Promise<AddedIssuer> {
  const email = input.email.trim().toLowerCase();
  const displayName = input.displayName.trim();
  if (email.length > EMAIL_MAX || !EMAIL_PATTERN.test(email)) {
    throw new AddIssuerError('El correo no es válido');
  }
  if (displayName.length < DISPLAY_NAME_MIN || displayName.length > DISPLAY_NAME_MAX) {
    throw new AddIssuerError(`El nombre debe tener entre ${DISPLAY_NAME_MIN} y ${DISPLAY_NAME_MAX} caracteres`);
  }
  if (input.password.length < ISSUER_PASSWORD_MIN_LENGTH || input.password.length > ISSUER_PASSWORD_MAX_LENGTH) {
    throw new AddIssuerError(
      `La contraseña debe tener entre ${ISSUER_PASSWORD_MIN_LENGTH} y ${ISSUER_PASSWORD_MAX_LENGTH} caracteres`,
    );
  }

  const passwordHash = await hashPassword(input.password);
  try {
    return await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: { email, displayName, passwordHash, role: Role.ISSUER },
        select: { id: true, email: true, displayName: true },
      });
      await tx.auditLog.create({
        data: {
          action: 'ISSUER_PROVISIONED',
          outcome: 'SUCCESS',
          actorId: null,
          targetType: 'user',
          targetId: user.id,
          metadata: { actor: 'lab-script', email: user.email, role: Role.ISSUER },
        },
      });
      return user;
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
      throw new AddIssuerError('Ya existe una cuenta con ese correo');
    }
    throw error;
  }
}
