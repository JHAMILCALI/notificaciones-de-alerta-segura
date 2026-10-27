import type { Permission } from '@alertasegura/shared'
import { Navigate, Outlet, useLocation } from 'react-router'
import { useAuth } from './auth-context.ts'

/**
 * Ruta de interfaz protegida: redirige a /login si no hay sesión. Es solo UX; la API vuelve a
 * comprobar sesión, CSRF, rol y propiedad en cada petición.
 */
export function ProtectedRoute({ permission }: { permission?: Permission }) {
  const { state } = useAuth()
  const location = useLocation()

  if (state.status === 'loading') {
    return (
      <p role="status" className="muted">
        Comprobando sesión…
      </p>
    )
  }
  if (state.status === 'anonymous') {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  if (permission !== undefined && !state.user.permissions.includes(permission)) {
    return (
      <section className="card" aria-labelledby="forbidden-title">
        <h1 id="forbidden-title">Acceso no permitido</h1>
        <p>Tu rol ({state.user.role}) no incluye el permiso necesario para esta sección.</p>
      </section>
    )
  }
  return <Outlet />
}
