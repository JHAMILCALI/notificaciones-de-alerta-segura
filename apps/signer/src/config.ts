export interface SignerConfig {
  /** Socket Unix (Linux) o named pipe (Windows, solo desarrollo). */
  socketPath: string;
  privateKeyPath: string | undefined;
}

/** Ruta por defecto del contrato: `/run/signer/signer.sock`; en Windows, una named pipe de laboratorio. */
export const DEFAULT_SOCKET_PATH =
  process.platform === 'win32' ? '\\\\.\\pipe\\alertasegura-signer' : '/run/signer/signer.sock';

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SignerConfig {
  const socketPath = env.SIGNER_SOCKET_PATH?.trim();
  const privateKeyPath = env.SIGNER_PRIVATE_KEY_PATH?.trim();
  return {
    socketPath: socketPath ? socketPath : DEFAULT_SOCKET_PATH,
    privateKeyPath: privateKeyPath ? privateKeyPath : undefined,
  };
}
