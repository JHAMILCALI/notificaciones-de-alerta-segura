import { useCallback } from 'react'
import { useResource } from '../../hooks/useResource.ts'
import { useApi } from '../../lib/api-context.ts'

const dateFormat = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' })

export function UsersPage() {
  const api = useApi()
  const load = useCallback(() => api.listUsers(), [api])
  const resource = useResource(load)

  return (
    <section className="card" aria-labelledby="users-title">
      <h1 id="users-title">Usuarios</h1>
      {resource.status === 'loading' && <p role="status">Cargando usuarios…</p>}
      {resource.status === 'error' && (
        <p role="alert" className="alert error">
          {resource.message}
        </p>
      )}
      {resource.status === 'ready' &&
        (resource.data.length === 0 ? (
          <p>No hay usuarios.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Usuarios registrados</caption>
              <thead>
                <tr>
                  <th scope="col">Nombre</th>
                  <th scope="col">Correo</th>
                  <th scope="col">Rol</th>
                  <th scope="col">Estado</th>
                  <th scope="col">Creado</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((user) => (
                  <tr key={user.id}>
                    <td>{user.displayName}</td>
                    <td>{user.email}</td>
                    <td>{user.role}</td>
                    <td>{user.status}</td>
                    <td>
                      <time dateTime={user.createdAt}>{dateFormat.format(new Date(user.createdAt))}</time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </section>
  )
}
