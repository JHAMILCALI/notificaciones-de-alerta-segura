import { describe, expect, it } from 'vitest';
import { canonicalize, CanonicalizationError } from '../src/index.ts';

/** Construye el double IEEE 754 a partir de su representación hexadecimal de 64 bits. */
function doubleFromHex(hex: string): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
}

describe('RFC 8785 §3.2.2 - ejemplo de serialización', () => {
  it('produce exactamente la salida del RFC', () => {
    // Entrada del RFC (texto JSON, con escapes \u y números en notaciones variadas).
    const input =
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
      '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"/","literals":[null,true,false]}';
    const expected =
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
      '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
    expect(canonicalize(JSON.parse(input))).toBe(expected);
  });
});

describe('RFC 8785 §3.2.3 - ordenación de propiedades', () => {
  it('ordena por unidades de código UTF-16 (el emoji va antes que U+FB33)', () => {
    const input = JSON.parse(
      `{
        "\\u20ac": "Euro Sign",
        "\\r": "Carriage Return",
        "\\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\\ud83d\\ude00": "Emoji: Grinning Face",
        "\\u0080": "Control",
        "\\u00f6": "Latin Small Letter O With Diaeresis"
      }`,
    ) as Record<string, string>;
    const out = canonicalize(input);
    // Orden esperado del RFC: CR, 1, U+0080, ö, €, 😀 (D83D), U+FB33 (la salida es texto, no un objeto reanalizado)
    expect(out).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",' +
        '"€":"Euro Sign","\u{1f600}":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  it('no usa el orden de puntos de código: U+E000 va después de un emoji en UTF-16', () => {
    // Por punto de código U+E000 < U+1F600, pero por UTF-16 D83D < E000.
    expect(canonicalize({ '': 1, '\u{1f600}': 2 })).toBe('{"\u{1f600}":2,"":1}');
  });
});

describe('RFC 8785 Apéndice B - serialización de números', () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['0000000000000000', '0'],
    ['8000000000000000', '0'], // menos cero se normaliza
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555554', '333333333.33333325'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555556', '333333333.3333334'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
  ];

  it.each(cases)('IEEE 0x%s -> %s', (hex, expected) => {
    expect(canonicalize(doubleFromHex(hex))).toBe(expected);
  });

  it.each([
    ['7fffffffffffffff', 'NaN'],
    ['7ff0000000000000', '+Infinity'],
    ['fff0000000000000', '-Infinity'],
  ])('IEEE 0x%s (%s) se rechaza', (hex) => {
    expect(() => canonicalize(doubleFromHex(hex))).toThrow(CanonicalizationError);
  });
});

describe('Primitivos y escape de cadenas', () => {
  it('serializa literales y estructuras vacías', () => {
    expect(canonicalize(null)).toBe('null');
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize(false)).toBe('false');
    expect(canonicalize([])).toBe('[]');
    expect(canonicalize({})).toBe('{}');
    expect(canonicalize([[], {}, [null]])).toBe('[[],{},[null]]');
  });

  it('usa el escape mínimo: controles en \\u00xx minúscula y el resto literal', () => {
    expect(canonicalize('\b\t\n\f\r"\\')).toBe('"\\b\\t\\n\\f\\r\\"\\\\"');
    expect(canonicalize('\u0000\u0001\u001f')).toBe('"\\u0000\\u0001\\u001f"');
    expect(canonicalize('/ \u007f   é € \u{1f600}')).toBe('"/ \u007f   é € \u{1f600}"');
  });

  it('no incluye espacios y preserva el orden de arreglos', () => {
    expect(canonicalize({ b: [3, 1, 2], a: { d: 1, c: 2 } })).toBe('{"a":{"c":2,"d":1},"b":[3,1,2]}');
  });

  it('es independiente del orden de inserción', () => {
    expect(canonicalize({ a: 1, b: 2 })).toBe(canonicalize({ b: 2, a: 1 }));
  });

  it('acepta objetos sin prototipo y la clave __proto__ como dato', () => {
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, { b: 1, a: 2 });
    expect(canonicalize(bare)).toBe('{"a":2,"b":1}');
    expect(canonicalize(JSON.parse('{"__proto__":1,"a":2}'))).toBe('{"__proto__":1,"a":2}');
  });

  it('permite referencias compartidas que no son ciclos', () => {
    const shared = { x: 1 };
    expect(canonicalize({ a: shared, b: [shared] })).toBe('{"a":{"x":1},"b":[{"x":1}]}');
  });
});

describe('Rechazo de valores no representables (I-JSON)', () => {
  const cases: ReadonlyArray<readonly [string, () => unknown, string]> = [
    ['undefined', () => undefined, 'UNSUPPORTED_TYPE'],
    ['undefined como miembro', () => ({ a: undefined }), 'UNSUPPORTED_TYPE'],
    ['función', () => () => 1, 'UNSUPPORTED_TYPE'],
    ['BigInt', () => 10n, 'UNSUPPORTED_TYPE'],
    ['Symbol', () => Symbol('x'), 'UNSUPPORTED_TYPE'],
    ['clave Symbol', () => ({ [Symbol('k')]: 1 }), 'UNSUPPORTED_TYPE'],
    ['NaN', () => NaN, 'NON_FINITE_NUMBER'],
    ['Infinity', () => ({ n: Infinity }), 'NON_FINITE_NUMBER'],
    ['-Infinity', () => [-Infinity], 'NON_FINITE_NUMBER'],
    ['Date', () => new Date(0), 'UNSUPPORTED_TYPE'],
    ['Map', () => new Map(), 'UNSUPPORTED_TYPE'],
    ['instancia de clase', () => new (class Foo {})(), 'UNSUPPORTED_TYPE'],
    ['hueco en arreglo', () => [1, , 3], 'UNSUPPORTED_TYPE'],
    ['surrogate alto suelto', () => 'a\ud800b', 'LONE_SURROGATE'],
    ['surrogate bajo suelto', () => 'a\udc00', 'LONE_SURROGATE'],
    ['surrogate suelto en clave', () => ({ '\ud83d': 1 }), 'LONE_SURROGATE'],
    ['par invertido', () => '\ude00\ud83d', 'LONE_SURROGATE'],
  ];

  it.each(cases)('rechaza %s', (_name, make, code) => {
    let caught: unknown;
    try {
      canonicalize(make());
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CanonicalizationError);
    expect((caught as CanonicalizationError).code).toBe(code);
  });

  it('rechaza ciclos en objetos y arreglos', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    expect(() => canonicalize(obj)).toThrow(/circular/);
    const arr: unknown[] = [];
    arr.push([arr]);
    expect(() => canonicalize(arr)).toThrowError(CanonicalizationError);
  });

  it('rechaza profundidad excesiva sin desbordar la pila', () => {
    let deep: unknown = 1;
    for (let i = 0; i < 1000; i++) deep = [deep];
    expect(() => canonicalize(deep)).toThrowError(/Profundidad/);
  });

  it('acepta un par de surrogates bien formado', () => {
    expect(canonicalize('😀')).toBe('"\u{1f600}"');
  });
});
