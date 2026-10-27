import type { Permission } from '@alertasegura/shared'
import { Link } from 'react-router'
import { useAuth } from '../auth/auth-context.ts'

const ROLE_LABELS = {
  ADMIN: 'Administrador',
  ISSUER: 'Emisor',
  AUDITOR: 'Auditor',
} as const

export function DashboardPage() {
  const { state } = useAuth()
  if (state.status !== 'authenticated') return null
  const { user } = state
  const can = (permission: Permission) => user.permissions.includes(permission)

  return (
    <>
      <section className="card" aria-labelledby="panel-title">
        <h1 id="panel-title">Panel</h1>
        <dl className="kv">
          <dt>Usuario</dt>
          <dd>{user.displayName}</dd>
          <dt>Correo</dt>
          <dd>{user.email}</dd>
          <dt>Rol</dt>
          <dd>
            {ROLE_LABELS[user.role]} <span className="muted">({user.role})</span>
          </dd>
          <dt>Permisos</dt>
          <dd>
            <ul className="chips" aria-label="Permisos">
              {user.permissions.map((permission) => (
                <li key={permission}>
                  <code>{permission}</code>
                </li>
              ))}
            </ul>
          </dd>
        </dl>
      </section>
      <section className="card" aria-labelledby="secciones-title">
        <h2 id="secciones-title">Secciones disponibles</h2>
        <ul className="link-list">
          {can('users:read') && (
            <li>
              <Link to="/admin/usuarios">Usuarios</Link>
            </li>
          )}
          {can('drafts:read-own') && (
            <li>
              <Link to="/admin/borradores">Borradores</Link>
            </li>
          )}
          {can('audit:read') && (
            <li>
              <Link to="/admin/auditoria">Auditoría</Link>
            </li>
          )}
          <li>
            <Link to="/laboratorio/criptografia">Laboratorio criptográfico</Link>
          </li>
        </ul>
      </section>
    </>
  )
}
