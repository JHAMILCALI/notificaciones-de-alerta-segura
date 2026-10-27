import { isApiError } from '../../lib/api.ts'

export function describeRetryAfter(seconds: number | null): string {
  if (seconds === null) return 'unos minutos'
  if (seconds < 60) return `${Math.max(1, seconds)} segundos`
  const minutes = Math.ceil(seconds / 60)
  return minutes === 1 ? '1 minuto' : `${minutes} minutos`
}

export function loginErrorMessage(error: unknown): string {
  if (isApiError(error)) {
    if (error.status === 429 || error.code === 'RATE_LIMITED') {
      return `Demasiados intentos. Vuelve a intentarlo en ${describeRetryAfter(error.retryAfterSeconds)}.`
    }
    // Mensaje deliberadamente genérico: no revela si la cuenta existe o está deshabilitada.
    if (error.status === 401 || error.code === 'INVALID_CREDENTIALS') {
      return 'Correo o contraseña incorrectos.'
    }
    if (error.code === 'CSRF_INVALID') {
      return 'No se pudo validar la solicitud de seguridad. Recarga la página e inténtalo de nuevo.'
    }
    if (error.code === 'NETWORK_ERROR') return 'No se pudo conectar con el servidor. Revisa tu conexión.'
    if (error.code === 'VALIDATION_FAILED') return 'Revisa el correo y la contraseña ingresados.'
  }
  return 'No se pudo iniciar sesión. Inténtalo de nuevo más tarde.'
}
