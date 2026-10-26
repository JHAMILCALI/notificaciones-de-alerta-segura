import { Controller, Get } from '@nestjs/common';
import type { TrustManifestResponse } from '@alertasegura/shared';
import { Public } from '../../common/decorators/metadata';
import { TrustService } from './trust.service';

/** Lectura pública del manifiesto de confianza. No hay escrituras: el manifiesto lo emite la CLI offline. */
@Controller('trust')
export class TrustController {
  constructor(private readonly trust: TrustService) {}

  @Public()
  @Get('manifest')
  manifest(): Promise<TrustManifestResponse> {
    return this.trust.manifest();
  }
}
