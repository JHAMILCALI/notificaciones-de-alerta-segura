import { Global, Module } from '@nestjs/common';

export const CLOCK = Symbol('CLOCK');

/** Reloj inyectable: las pruebas lo controlan para vencer alertas y estados sin esperar. */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

@Global()
@Module({
  providers: [{ provide: CLOCK, useValue: systemClock }],
  exports: [CLOCK],
})
export class ClockModule {}

/** ISO 8601 UTC con segundos exactos, como en los documentos firmados (`2026-10-26T14:05:09Z`). */
export function toIsoSeconds(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Redondea hacia abajo al segundo: los documentos firmados no llevan fracciones. */
export function floorToSecond(date: Date): Date {
  return new Date(Math.floor(date.getTime() / 1000) * 1000);
}
