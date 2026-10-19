export interface VerificationInput {
  payload: BufferSource;
  signature: BufferSource;
  publicKey: CryptoKey;
}

export async function verifyEcdsa(input: VerificationInput): Promise<boolean> {
  return globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    input.publicKey,
    input.signature,
    input.payload,
  );
}
