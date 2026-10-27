import { loadConfig } from './config.ts';
import { loadSigningKey } from './key.ts';
import { consoleLogger, createSignerServer, listenOnSocket } from './server.ts';

const config = loadConfig();
// La clave se lee una sola vez, aquí. Si falta, el servicio arranca y responde 503 KEY_UNAVAILABLE.
const key = await loadSigningKey(config.privateKeyPath);
if (key === null) consoleLogger.error('key_unavailable_at_startup');

const server = createSignerServer({ key });
await listenOnSocket(server, config.socketPath);
consoleLogger.info('listening', key === null ? {} : { key_id: key.keyId });

function shutdown(): void {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
