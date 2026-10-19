export async function sha256(data: BufferSource): Promise<ArrayBuffer> {
  return globalThis.crypto.subtle.digest('SHA-256', data);
}
