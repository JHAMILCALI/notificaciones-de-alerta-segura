import {
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import type { ZodType } from 'zod';
import { VALIDATE_KEY, type ValidationSchemas } from '../decorators/metadata';
import { validationFailed } from '../http/api-exception';

interface Issue {
  path: string;
  message: string;
}

function parse(
  schema: ZodType,
  value: unknown,
  prefix: string,
  issues: Issue[],
): unknown {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  for (const issue of result.error.issues) {
    // Solo ruta y mensaje del esquema: nunca se repite el valor enviado.
    const path = [prefix, ...issue.path.map(String)].filter(Boolean).join('.');
    issues.push({ path: path || prefix || '(raíz)', message: issue.message });
  }
  return undefined;
}

/**
 * Control 4: validación con los esquemas Zod de `@alertasegura/shared`.
 * Es un guard (y no un pipe) porque el contrato exige validar ANTES del RBAC y los pipes de
 * Nest se ejecutan después de todos los guards.
 */
@Injectable()
export class ZodValidationGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const schemas = this.reflector.get<ValidationSchemas | undefined>(
      VALIDATE_KEY,
      context.getHandler(),
    );
    if (!schemas) return true;
    const req = context.switchToHttp().getRequest<Request>();
    const issues: Issue[] = [];
    const validated: NonNullable<Request['validated']> = {};
    if (schemas.params)
      validated.params = parse(schemas.params, req.params, 'params', issues);
    if (schemas.query)
      validated.query = parse(schemas.query, req.query, 'query', issues);
    if (schemas.body)
      validated.body = parse(schemas.body, req.body, 'body', issues);
    if (issues.length > 0) throw validationFailed(issues);
    req.validated = validated;
    return true;
  }
}
