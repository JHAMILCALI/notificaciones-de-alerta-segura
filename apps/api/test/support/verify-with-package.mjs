// Verifica sobres firmados con el paquete REAL @alertasegura/verification (el que usará la PWA).
// El paquete es ESM puro y las pruebas de la API corren como CommonJS bajo Jest, así que la verificación se
// ejecuta en un proceso Node aparte: entra JSON por stdin y sale JSON por stdout.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const entry = path.resolve(
  import.meta.dirname,
  '../../../../packages/verification/dist/index.js',
);
const pkg = await import(pathToFileURL(entry).href);

const { jwk, envelopes } = JSON.parse(readFileSync(0, 'utf8'));
const kid = await pkg.computeKid(jwk);

const results = [];
for (const envelope of envelopes) {
  const bytes = pkg.base64UrlToBytes(envelope.payload_canonico);
  const text = new TextDecoder().decode(bytes);
  const document = JSON.parse(text);
  results.push({
    document,
    // Los bytes guardados son exactamente la canonicalización JCS del documento.
    canonical: pkg.canonicalize(document) === text,
    hashOk: (await pkg.sha256Hex(text)) === envelope.hash_payload,
    keyIdOk: kid === envelope.key_id && document.key_id === envelope.key_id,
    signatureOk: await pkg.verifyCanonicalSignature({
      payload: document,
      signatureB64u: envelope.firma,
      publicKeyJwk: jwk,
    }),
  });
}
process.stdout.write(JSON.stringify(results));
