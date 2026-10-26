import { describe, expect, it } from 'vitest'
import { formatDateTimeBolivia } from './format.ts'

describe('formatDateTimeBolivia', () => {
  it('muestra la hora de Bolivia (UTC−4), no la del navegador', () => {
    // 12:00 UTC son las 08:00 en La Paz.
    expect(formatDateTimeBolivia('2026-10-19T12:00:00Z')).toMatch(/8:00/)
    // 02:00 UTC del día 20 siguen siendo el día 19 (22:00) en La Paz.
    expect(formatDateTimeBolivia('2026-10-20T02:00:00Z')).toMatch(/19/)
    expect(formatDateTimeBolivia('2026-10-20T02:00:00Z')).toMatch(/10:00/)
  })

  it('devuelve el texto original si la fecha no es válida', () => {
    expect(formatDateTimeBolivia('no-es-fecha')).toBe('no-es-fecha')
  })
})
