import { useCallback, useState } from 'react'
import { useResource } from '../../hooks/useResource.ts'
import { useApi } from '../../lib/api-context.ts'

const dateFormat = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'medium' })
const LIMITS = [25, 50, 100, 200]

export function AuditPage() {
  const api = useApi()
  const [limit, setLimit] = useState(50)
  const load = useCallback(() => api.listAudit(limit), [api, limit])
  const resource = useResource(load)

  return (
    <section className="card" aria-labelledby="audit-title">
      <h1 id="audit-title">Auditoría</h1>
      <div className="field inline">
        <label htmlFor="audit-limit">Registros</label>
        <select id="audit-limit" value={limit} onChange={(event) => setLimit(Number(event.target.value))}>
          {LIMITS.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <button type="button" onClick={resource.reload}>
          Actualizar
        </button>
      </div>
      {resource.status === 'loading' && <p role="status">Cargando registros…</p>}
      {resource.status === 'error' && (
        <p role="alert" className="alert error">
          {resource.message}
        </p>
      )}
      {resource.status === 'ready' &&
        (resource.data.length === 0 ? (
          <p>No hay registros.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Registro de auditoría, más recientes primero</caption>
              <thead>
                <tr>
                  <th scope="col">Fecha</th>
                  <th scope="col">Acción</th>
                  <th scope="col">Resultado</th>
                  <th scope="col">Actor</th>
                  <th scope="col">IP</th>
                  <th scope="col">Detalle</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((entry) => (
                  <tr key={entry.id}>
                    <td>
                      <time dateTime={entry.occurredAt}>{dateFormat.format(new Date(entry.occurredAt))}</time>
                    </td>
                    <td>
                      <code>{entry.action}</code>
                    </td>
                    <td>{entry.outcome}</td>
                    <td className="mono">{entry.actorId ?? '—'}</td>
                    <td>{entry.ip ?? '—'}</td>
                    <td>
                      {entry.targetType !== null && (
                        <span>
                          {entry.targetType}
                          {entry.targetId !== null ? `:${entry.targetId}` : ''}{' '}
                        </span>
                      )}
                      {Object.keys(entry.metadata).length > 0 && <code>{JSON.stringify(entry.metadata)}</code>}
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
