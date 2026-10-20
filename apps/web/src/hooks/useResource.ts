import { useCallback, useEffect, useState } from 'react'
import { isApiError } from '../lib/api.ts'

export type ResourceState<T> =
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'error'; message: string }

export function describeError(error: unknown): string {
  if (isApiError(error)) {
    if (error.code === 'RATE_LIMITED') return 'Demasiadas solicitudes. Espera un momento e inténtalo de nuevo.'
    if (error.code === 'FORBIDDEN') return 'No tienes permiso para ver este contenido.'
    return error.message
  }
  return 'Ocurrió un error inesperado.'
}

interface Settled<T> {
  loader: () => Promise<T>
  version: number
  outcome: { ok: true; data: T } | { ok: false; message: string }
}

/**
 * Carga un recurso de la API con estados cargando / listo / error.
 * `loader` debe ser estable (useCallback): si cambia, o se llama a `reload()`, se vuelve a cargar.
 */
export function useResource<T>(loader: () => Promise<T>): ResourceState<T> & { reload(): void } {
  const [settled, setSettled] = useState<Settled<T> | null>(null)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    let cancelled = false
    loader().then(
      (data) => {
        if (!cancelled) setSettled({ loader, version, outcome: { ok: true, data } })
      },
      (error: unknown) => {
        if (!cancelled) setSettled({ loader, version, outcome: { ok: false, message: describeError(error) } })
      },
    )
    return () => {
      cancelled = true
    }
  }, [loader, version])

  const reload = useCallback(() => setVersion((v) => v + 1), [])

  // El estado "cargando" se deriva: el resultado guardado solo vale para este loader y esta versión.
  const current = settled !== null && settled.loader === loader && settled.version === version ? settled : null
  if (current === null) return { status: 'loading', reload }
  return current.outcome.ok
    ? { status: 'ready', data: current.outcome.data, reload }
    : { status: 'error', message: current.outcome.message, reload }
}
