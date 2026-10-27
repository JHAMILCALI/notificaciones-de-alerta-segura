import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import type { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { API_PREFIX } from '@alertasegura/shared';
import { mapError } from './common/filters/error-mapper';
import { APP_CONFIG } from './config/config.module';
import type { AppConfig } from './config/env';

/**
 * Configuración HTTP común a `main.ts` y a las pruebas e2e (así se prueba lo que se despliega).
 * Debe llamarse con la app creada con `bodyParser` por defecto (Nest registra el parser JSON).
 */
export async function configureApp(app: NestExpressApplication): Promise<void> {
  const config = app.get<AppConfig>(APP_CONFIG);

  app.setGlobalPrefix(API_PREFIX.replace(/^\//, ''));
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  // La API solo devuelve JSON: ninguna respuesta debe poder cargar recursos, incrustarse ni enviar formularios.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
        },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );
  app.use((_req: Request, res: Response, next: NextFunction) => {
    // Las respuestas de la API llevan datos de sesión o personales: nada se cachea.
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.useBodyParser('json', { limit: config.bodyLimit });
  app.use(cookieParser());
  // Sin CORS: el navegador ve un único origen (proxy de Vite).
  app.enableShutdownHooks();

  await app.init();

  // Errores de middleware (cuerpo JSON malformado o demasiado grande) no pasan por los filtros
  // de Nest; este manejador final los devuelve también como `ApiError`.
  app.use(
    (error: unknown, _req: Request, res: Response, next: NextFunction) => {
      if (res.headersSent) {
        next(error);
        return;
      }
      const mapped = mapError(error);
      res.status(mapped.status).json(mapped.body);
    },
  );
}
