import { LOCALE_BOLIVIA, ZONA_HORARIA_BOLIVIA } from '@alertasegura/shared'

const dateTimeFormat = new Intl.DateTimeFormat(LOCALE_BOLIVIA, {
  dateStyle: 'medium',
  timeStyle: 'short',
  timeZone: ZONA_HORARIA_BOLIVIA,
})

/** Fecha y hora en la zona de Bolivia (America/La_Paz, UTC−4), con formato es-BO. Acepta ISO 8601. */
export function formatDateTimeBolivia(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : dateTimeFormat.format(date)
}
