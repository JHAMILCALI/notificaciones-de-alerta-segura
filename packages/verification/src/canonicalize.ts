import { CanonicalizationError } from './errors.ts';

/** Profundidad máxima admitida; evita desbordar la pila con entradas hostiles. */
const MAX_DEPTH = 256;

function assertWellFormed(text: string, what: string): void {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      throw new CanonicalizationError('LONE_SURROGATE', `${what} contiene un surrogate suelto (I-JSON)`);
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new CanonicalizationError('LONE_SURROGATE', `${what} contiene un surrogate suelto (I-JSON)`);
    }
  }
}

function serializeString(text: string, what: string): string {
  assertWellFormed(text, what);
  // Con cadenas bien formadas, JSON.stringify produce exactamente el escape mínimo de RFC 8785 §3.2.2.2:
  // \b \t \n \f \r \" \\ y \u00xx en minúsculas para el resto de controles; el resto, literal.
  return JSON.stringify(text);
}

function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError('NON_FINITE_NUMBER', 'NaN e Infinity no son JSON válido (I-JSON)');
  }
  // RFC 8785 §3.2.2.3: Number::toString de ECMAScript. -0 se serializa como "0".
  return Object.is(value, -0) ? '0' : String(value);
}

function compareUtf16(a: string, b: string): number {
  // Los operadores < y > comparan por unidades de código UTF-16, tal como exige RFC 8785 §3.2.3.
  return a < b ? -1 : a > b ? 1 : 0;
}

function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function serialize(value: unknown, ancestors: Set<object>, depth: number, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value);
    case 'string':
      return serializeString(value, `La cadena en ${path}`);
    case 'object':
      break;
    default:
      throw new CanonicalizationError(
        'UNSUPPORTED_TYPE',
        `Tipo no representable en JSON en ${path}: ${describeType(value)}`,
      );
  }

  const objectValue: object = value;
  if (depth >= MAX_DEPTH) {
    throw new CanonicalizationError('MAX_DEPTH', `Profundidad máxima (${MAX_DEPTH}) superada en ${path}`);
  }
  if (ancestors.has(objectValue)) {
    throw new CanonicalizationError('CYCLE', `Referencia circular en ${path}`);
  }
  ancestors.add(objectValue);
  try {
    if (Array.isArray(objectValue)) {
      const parts: string[] = [];
      for (let i = 0; i < objectValue.length; i++) {
        if (!(i in objectValue)) {
          throw new CanonicalizationError('UNSUPPORTED_TYPE', `Hueco (undefined) en ${path}[${i}]`);
        }
        parts.push(serialize(objectValue[i], ancestors, depth + 1, `${path}[${i}]`));
      }
      return `[${parts.join(',')}]`;
    }

    const proto: unknown = Object.getPrototypeOf(objectValue);
    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalizationError(
        'UNSUPPORTED_TYPE',
        `Solo se admiten objetos planos (no Date, Map, clases...) en ${path}`,
      );
    }
    if (Object.getOwnPropertySymbols(objectValue).length > 0) {
      throw new CanonicalizationError('UNSUPPORTED_TYPE', `Clave de tipo symbol en ${path}`);
    }

    const record = objectValue as Record<string, unknown>;
    const keys = Object.keys(record).sort(compareUtf16);
    const parts: string[] = [];
    for (const key of keys) {
      const member = serializeString(key, `La clave ${JSON.stringify(key)} de ${path}`);
      parts.push(`${member}:${serialize(record[key], ancestors, depth + 1, `${path}.${key}`)}`);
    }
    return `{${parts.join(',')}}`;
  } finally {
    ancestors.delete(objectValue);
  }
}

/**
 * Canonicalización JSON según RFC 8785 (JCS).
 *
 * - Claves ordenadas por unidades de código UTF-16.
 * - Números según ECMAScript (`-0` → `0`, notación exponencial donde corresponda).
 * - Escape mínimo de cadenas.
 * - Rechaza (CanonicalizationError): NaN, Infinity, undefined, funciones, bigint, symbol,
 *   objetos no planos, huecos de arrays, ciclos y surrogates sueltos.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, new Set<object>(), 0, '$');
}
