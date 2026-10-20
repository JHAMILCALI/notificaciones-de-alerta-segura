import { useState } from 'react'
import { Link, NavLink, Outlet } from 'react-router'
import { useAuth } from '../features/auth/auth-context.ts'

export function Layout() {
  const { state, logout } = useAuth()
  const [loggingOut, setLoggingOut] = useState(false)

  async function onLogout() {
    setLoggingOut(true)
    try {
      await logout()
    } catch {
      // El estado local ya pasó a anónimo; el fallo solo afecta a la limpieza remota.
    } finally {
      setLoggingOut(false)
    }
  }

  return (
    <>
      <a className="skip-link" href="#contenido">
        Saltar al contenido
      </a>
      <header className="site-header">
        <div className="container header-inner">
          <Link to="/" className="brand">
            AlertaSegura
          </Link>
          <nav aria-label="Principal" className="nav">
            <NavLink to="/" end>
              Inicio
            </NavLink>
            <NavLink to="/laboratorio/criptografia">Laboratorio</NavLink>
            {state.status === 'authenticated' ? (
              <>
                <NavLink to="/panel">Panel</NavLink>
                <button type="button" className="link-button" onClick={() => void onLogout()} disabled={loggingOut}>
                  Salir
                </button>
              </>
            ) : (
              <NavLink to="/login">Ingresar</NavLink>
            )}
          </nav>
        </div>
      </header>
      <main id="contenido" className="container" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="site-footer container">
        <small>AlertaSegura · Las comprobaciones de rol en pantalla son solo de interfaz; la API decide el acceso.</small>
      </footer>
    </>
  )
}
