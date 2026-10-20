import { CreateDraftRequestSchema, type Severity } from '@alertasegura/shared'
import { useCallback, useState, type FormEvent } from 'react'
import { describeError, useResource } from '../../hooks/useResource.ts'
import { useApi } from '../../lib/api-context.ts'

const SEVERITY_LABELS: Record<Severity, string> = {
  INFO: 'Informativa',
  WARNING: 'Advertencia',
  CRITICAL: 'Crítica',
}
const SEVERITIES: Severity[] = ['INFO', 'WARNING', 'CRITICAL']

const dateFormat = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' })

export function DraftsPage() {
  const api = useApi()
  const load = useCallback(() => api.listDrafts(), [api])
  const resource = useResource(load)
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [severity, setSeverity] = useState<Severity>('INFO')
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    const parsed = CreateDraftRequestSchema.safeParse({ title, body, severity })
    if (!parsed.success) {
      setFormError('El título debe tener entre 5 y 140 caracteres y el mensaje entre 10 y 4000.')
      return
    }
    setSubmitting(true)
    setFormError(null)
    try {
      await api.createDraft(parsed.data)
      setTitle('')
      setBody('')
      setSeverity('INFO')
      resource.reload()
    } catch (error) {
      setFormError(describeError(error))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <section className="card" aria-labelledby="new-draft-title">
        <h1 id="new-draft-title">Nuevo borrador</h1>
        <p className="muted">
          Los borradores aún no se publican: la firma y publicación de alertas llegan en la semana 2.
        </p>
        <form onSubmit={(event) => void onSubmit(event)} noValidate>
          <div className="field">
            <label htmlFor="draft-title">Título</label>
            <input
              id="draft-title"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              maxLength={140}
              required
              disabled={submitting}
            />
          </div>
          <div className="field">
            <label htmlFor="draft-body">Mensaje</label>
            <textarea
              id="draft-body"
              value={body}
              onChange={(event) => setBody(event.target.value)}
              rows={5}
              maxLength={4000}
              required
              disabled={submitting}
            />
          </div>
          <div className="field">
            <label htmlFor="draft-severity">Severidad</label>
            <select
              id="draft-severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value as Severity)}
              disabled={submitting}
            >
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {SEVERITY_LABELS[value]}
                </option>
              ))}
            </select>
          </div>
          <div role="alert" className={formError ? 'alert error' : undefined}>
            {formError}
          </div>
          <button type="submit" className="primary" disabled={submitting}>
            {submitting ? 'Guardando…' : 'Crear borrador'}
          </button>
        </form>
      </section>

      <section className="card" aria-labelledby="my-drafts-title">
        <h2 id="my-drafts-title">Mis borradores</h2>
        {resource.status === 'loading' && <p role="status">Cargando borradores…</p>}
        {resource.status === 'error' && (
          <p role="alert" className="alert error">
            {resource.message}
          </p>
        )}
        {resource.status === 'ready' &&
          (resource.data.length === 0 ? (
            <p>Todavía no tienes borradores.</p>
          ) : (
            <ul className="draft-list">
              {resource.data.map((draft) => (
                <li key={draft.id}>
                  <h3>{draft.title}</h3>
                  <p className="muted">
                    {SEVERITY_LABELS[draft.severity]} ·{' '}
                    <time dateTime={draft.createdAt}>{dateFormat.format(new Date(draft.createdAt))}</time>
                  </p>
                  <p className="pre-wrap">{draft.body}</p>
                </li>
              ))}
            </ul>
          ))}
      </section>
    </>
  )
}
