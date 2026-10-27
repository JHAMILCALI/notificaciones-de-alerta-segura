import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { isApiError } from '../../lib/api.ts'
import { useApi } from '../../lib/api-context.ts'
import { AuthContext, type AuthContextValue, type AuthState } from './auth-context.ts'

/**
 * Estado de sesión: consulta `/auth/me` al cargar. La cookie de sesión es HttpOnly, así que el
 * frontend solo conoce al usuario por esa respuesta; nunca guarda tokens en el almacenamiento web.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const api = useApi()
  const [state, setState] = useState<AuthState>({ status: 'loading', user: null })

  useEffect(() => {
    let cancelled = false
    api
      .me()
      .then((user) => {
        if (!cancelled) setState({ status: 'authenticated', user })
      })
      .catch((error: unknown) => {
        // 401 = anónimo. Cualquier otro fallo (red, 5xx) también deja la interfaz sin sesión;
        // la API sigue siendo la que decide el acceso.
        if (!cancelled) setState({ status: 'anonymous', user: null })
        if (!isApiError(error) || error.status !== 401) {
          console.warn('No se pudo comprobar la sesión')
        }
      })
    // Una sesión caducada en cualquier petición devuelve la interfaz al estado anónimo.
    const unsubscribe = api.onUnauthenticated(() => {
      setState({ status: 'anonymous', user: null })
    })
    return () => {
      cancelled = true
      unsubscribe()
    }
  }, [api])

  const login = useCallback(
    async (email: string, password: string) => {
      const user = await api.login({ email, password })
      setState({ status: 'authenticated', user })
    },
    [api],
  )

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch (error) {
      // Si la sesión ya había caducado (401) igualmente se considera cerrada.
      if (!isApiError(error) || error.status !== 401) throw error
    } finally {
      setState({ status: 'anonymous', user: null })
    }
  }, [api])

  const value = useMemo<AuthContextValue>(() => ({ state, login, logout }), [state, login, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
