import {
  CreateDraftRequestSchema,
  DEPARTAMENTOS,
  DEPARTAMENTO_ETIQUETAS,
  NIVELES_ALERTA,
  NIVEL_ALERTA_ETIQUETAS,
  TIPOS_ALERTA,
  TIPO_ALERTA_ETIQUETAS,
  VIGENCIA_HORAS_MAX,
  VIGENCIA_HORAS_MIN,
  ZONA_HORARIA_BOLIVIA,
  type Draft,
  type NivelAlerta,
} from '@alertasegura/shared'
import { useCallback, useState, type FormEvent } from 'react'
import { describeError, useResource } from '../../hooks/useResource.ts'
import { isApiError } from '../../lib/api.ts'
import { useApi } from '../../lib/api-context.ts'
import { formatDateTimeBolivia } from '../../lib/format.ts'
import { useAuth } from '../auth/auth-context.ts'

const VIGENCIA_POR_DEFECTO = '24'

/** Insignia con el color del nivel; el texto siempre lo nombra (el color no es el único canal). */
function NivelBadge({ nivel }: { nivel: NivelAlerta }) {
  return <span className={`badge nivel nivel-${nivel.toLowerCase()}`}>{NIVEL_ALERTA_ETIQUETAS[nivel]}</span>
}

function zonaTexto(draft: Draft): string {
  const departamento = DEPARTAMENTO_ETIQUETAS[draft.zona.departamento]
  return draft.zona.municipio === null ? departamento : `${draft.zona.municipio}, ${departamento}`
}

/** Mensajes de campo en español; el esquema Zod del contrato decide qué es válido. */
const FIELD_MESSAGES: Record<string, string> = {
  tipo: 'Selecciona el tipo de alerta.',
  departamento: 'Selecciona el departamento.',
  municipio: 'El municipio, si lo indicas, debe tener entre 2 y 120 caracteres.',
  severidad: 'Selecciona el nivel de alerta.',
  mensaje: 'El mensaje debe tener entre 10 y 1000 caracteres.',
  vigenciaHoras: `La vigencia debe ser un número entero de horas entre ${VIGENCIA_HORAS_MIN} y ${VIGENCIA_HORAS_MAX}.`,
}

function cancelErrorMessage(error: unknown): string {
  if (isApiError(error)) {
    if (error.code === 'SIGNER_UNAVAILABLE') {
      return 'El servicio de firma no está disponible. La alerta no se canceló; inténtalo de nuevo en unos minutos.'
    }
    if (error.code === 'CONFLICT') return 'Esta alerta ya estaba cancelada.'
    if (error.code === 'FORBIDDEN') return 'Solo el emisor de la alerta puede cancelarla.'
    if (error.code === 'NOT_FOUND') return 'No se encontró la alerta.'
  }
  return describeError(error)
}

function publishErrorMessage(error: unknown): string {
  if (isApiError(error)) {
    if (error.code === 'SIGNER_UNAVAILABLE') {
      return 'El servicio de firma no está disponible. No se publicó nada; inténtalo de nuevo en unos minutos.'
    }
    if (error.code === 'CONFLICT') return 'Este borrador ya estaba publicado.'
    if (error.code === 'FORBIDDEN') return 'No tienes permiso para publicar este borrador.'
  }
  return describeError(error)
}

interface CancelControlsProps {
  alertaId: string
  confirming: boolean
  busy: boolean
  disabled: boolean
  onAsk(): void
  onBack(): void
  onConfirm(): void
}

function CancelControls({ alertaId, confirming, busy, disabled, onAsk, onBack, onConfirm }: CancelControlsProps) {
  if (!confirming) {
    return (
      <button type="button" onClick={onAsk} disabled={disabled} aria-label={`Cancelar la alerta ${alertaId}`}>
        Cancelar alerta
      </button>
    )
  }
  return (
    <div className="actions" role="group" aria-label="Confirmar cancelación">
      <p>La cancelación se firma y no se puede deshacer. ¿Cancelar esta alerta?</p>
      <button type="button" className="primary" onClick={onConfirm} disabled={disabled}>
        {busy ? 'Cancelando…' : 'Sí, cancelar alerta'}
      </button>
      <button type="button" onClick={onBack} disabled={disabled}>
        No, volver
      </button>
    </div>
  )
}

export function DraftsPage() {
  const api = useApi()
  const { state } = useAuth()
  const canPublish = state.user?.permissions.includes('alerts:publish') ?? false
  const canCancel = state.user?.permissions.includes('alerts:cancel') ?? false
  const load = useCallback(() => api.listDrafts(), [api])
  const resource = useResource(load)

  const [tipo, setTipo] = useState('')
  const [departamento, setDepartamento] = useState('')
  const [municipio, setMunicipio] = useState('')
  const [severidad, setSeveridad] = useState<NivelAlerta>('AMARILLA')
  const [mensaje, setMensaje] = useState('')
  const [vigencia, setVigencia] = useState(VIGENCIA_POR_DEFECTO)
  const [submitting, setSubmitting] = useState(false)
  const [formErrors, setFormErrors] = useState<string[]>([])

  const [publishingId, setPublishingId] = useState<string | null>(null)
  const [publishError, setPublishError] = useState<{ draftId: string; message: string } | null>(null)
  const [published, setPublished] = useState<string | null>(null)

  // Cancelar es irreversible: primero se pide confirmación (confirmingId) y luego se envía (cancellingId).
  const [confirmingId, setConfirmingId] = useState<string | null>(null)
  const [cancellingId, setCancellingId] = useState<string | null>(null)
  const [cancelled, setCancelled] = useState<ReadonlySet<string>>(new Set())
  const [cancelError, setCancelError] = useState<{ alertaId: string; message: string } | null>(null)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    const parsed = CreateDraftRequestSchema.safeParse({
      tipo,
      zona: { departamento, municipio: municipio.trim() === '' ? null : municipio.trim() },
      severidad,
      mensaje,
      vigenciaHoras: vigencia.trim() === '' ? Number.NaN : Number(vigencia),
    })
    if (!parsed.success) {
      const keys = new Set(parsed.error.issues.map((issue) => String(issue.path[issue.path.length - 1] ?? '')))
      setFormErrors(Object.keys(FIELD_MESSAGES).filter((key) => keys.has(key)).map((key) => FIELD_MESSAGES[key] ?? ''))
      return
    }
    setSubmitting(true)
    setFormErrors([])
    try {
      await api.createDraft(parsed.data)
      setTipo('')
      setDepartamento('')
      setMunicipio('')
      setSeveridad('AMARILLA')
      setMensaje('')
      setVigencia(VIGENCIA_POR_DEFECTO)
      resource.reload()
    } catch (error) {
      setFormErrors([describeError(error)])
    } finally {
      setSubmitting(false)
    }
  }

  async function onPublish(draftId: string) {
    if (publishingId !== null) return
    setPublishingId(draftId)
    setPublishError(null)
    setPublished(null)
    try {
      const alerta = await api.publishDraft(draftId)
      setPublished(alerta.id)
      resource.reload()
    } catch (error) {
      setPublishError({ draftId, message: publishErrorMessage(error) })
      // Un 409 significa que otro envío ya lo publicó: la lista debe reflejarlo.
      if (isApiError(error) && error.code === 'CONFLICT') resource.reload()
    } finally {
      setPublishingId(null)
    }
  }

  async function onCancel(alertaId: string) {
    if (cancellingId !== null) return
    setCancellingId(alertaId)
    setCancelError(null)
    try {
      await api.cancelAlert(alertaId)
      setCancelled((previous) => new Set(previous).add(alertaId))
      setConfirmingId(null)
    } catch (error) {
      setCancelError({ alertaId, message: cancelErrorMessage(error) })
      // Un 409 significa que ya estaba cancelada: no tiene sentido seguir ofreciendo cancelar.
      if (isApiError(error) && error.code === 'CONFLICT') {
        setCancelled((previous) => new Set(previous).add(alertaId))
        setConfirmingId(null)
      }
    } finally {
      setCancellingId(null)
    }
  }

  return (
    <>
      <section className="card" aria-labelledby="new-draft-title">
        <h1 id="new-draft-title">Nuevo borrador</h1>
        <p className="muted">
          Un borrador no es público hasta que lo publiques: al publicar se firma y queda inmutable. Las fechas se
          muestran en hora de Bolivia ({ZONA_HORARIA_BOLIVIA}).
        </p>
        <form onSubmit={(event) => void onSubmit(event)} noValidate>
          <div className="field">
            <label htmlFor="draft-tipo">Tipo de alerta</label>
            <select id="draft-tipo" value={tipo} onChange={(e) => setTipo(e.target.value)} disabled={submitting} required>
              <option value="">Selecciona…</option>
              {TIPOS_ALERTA.map((value) => (
                <option key={value} value={value}>
                  {TIPO_ALERTA_ETIQUETAS[value]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="draft-departamento">Departamento</label>
            <select
              id="draft-departamento"
              value={departamento}
              onChange={(e) => setDepartamento(e.target.value)}
              disabled={submitting}
              required
            >
              <option value="">Selecciona…</option>
              {DEPARTAMENTOS.map((value) => (
                <option key={value} value={value}>
                  {DEPARTAMENTO_ETIQUETAS[value]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="draft-municipio">Municipio (opcional)</label>
            <input
              id="draft-municipio"
              value={municipio}
              onChange={(e) => setMunicipio(e.target.value)}
              maxLength={120}
              disabled={submitting}
            />
          </div>
          <div className="field">
            <label htmlFor="draft-severidad">Nivel de alerta</label>
            <select
              id="draft-severidad"
              value={severidad}
              onChange={(e) => setSeveridad(e.target.value as NivelAlerta)}
              disabled={submitting}
            >
              {NIVELES_ALERTA.map((value) => (
                <option key={value} value={value}>
                  {NIVEL_ALERTA_ETIQUETAS[value]}
                </option>
              ))}
            </select>
            <p className="muted">
              Seleccionado: <NivelBadge nivel={severidad} />
            </p>
          </div>
          <div className="field">
            <label htmlFor="draft-mensaje">Mensaje</label>
            <textarea
              id="draft-mensaje"
              value={mensaje}
              onChange={(e) => setMensaje(e.target.value)}
              rows={5}
              maxLength={1000}
              required
              disabled={submitting}
            />
          </div>
          <div className="field">
            <label htmlFor="draft-vigencia">Vigencia (horas)</label>
            <input
              id="draft-vigencia"
              type="number"
              inputMode="numeric"
              min={VIGENCIA_HORAS_MIN}
              max={VIGENCIA_HORAS_MAX}
              step={1}
              value={vigencia}
              onChange={(e) => setVigencia(e.target.value)}
              required
              disabled={submitting}
            />
          </div>
          <div role="alert" className={formErrors.length > 0 ? 'alert error' : undefined}>
            {formErrors.map((message) => (
              <p key={message}>{message}</p>
            ))}
          </div>
          <button type="submit" className="primary" disabled={submitting}>
            {submitting ? 'Guardando…' : 'Crear borrador'}
          </button>
        </form>
      </section>

      <section className="card" aria-labelledby="my-drafts-title">
        <h2 id="my-drafts-title">Mis borradores</h2>
        <div role="status">
          {published !== null && (
            <p className="alert ok">
              Alerta publicada. Identificador: <code>{published}</code>
            </p>
          )}
        </div>
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
                  <h3>{TIPO_ALERTA_ETIQUETAS[draft.tipo]}</h3>
                  <p className="muted">
                    <NivelBadge nivel={draft.severidad} /> · {zonaTexto(draft)} · vigencia {draft.vigenciaHoras} h ·{' '}
                    <time dateTime={draft.createdAt}>{formatDateTimeBolivia(draft.createdAt)}</time>
                  </p>
                  <p className="pre-wrap">{draft.mensaje}</p>
                  {draft.status === 'PUBLISHED' ? (
                    <>
                      <p>
                        {draft.alertaId !== null && cancelled.has(draft.alertaId) ? (
                          <span className="badge bad">Cancelada</span>
                        ) : (
                          <span className="badge ok">Publicada</span>
                        )}
                        {draft.alertaId !== null && (
                          <>
                            {' '}
                            <code>{draft.alertaId}</code>
                          </>
                        )}
                      </p>
                      {canCancel && draft.alertaId !== null && !cancelled.has(draft.alertaId) && (
                        <CancelControls
                          alertaId={draft.alertaId}
                          confirming={confirmingId === draft.alertaId}
                          busy={cancellingId === draft.alertaId}
                          disabled={cancellingId !== null}
                          onAsk={() => {
                            setCancelError(null)
                            setConfirmingId(draft.alertaId)
                          }}
                          onBack={() => setConfirmingId(null)}
                          onConfirm={() => void onCancel(draft.alertaId as string)}
                        />
                      )}
                      {cancelError?.alertaId === draft.alertaId && (
                        <p role="alert" className="alert error">
                          {cancelError.message}
                        </p>
                      )}
                    </>
                  ) : (
                    <>
                      <p>
                        <span className="badge">Borrador</span>
                      </p>
                      {canPublish && (
                        <button
                          type="button"
                          className="primary"
                          onClick={() => void onPublish(draft.id)}
                          disabled={publishingId !== null}
                          aria-label={`Publicar borrador de ${TIPO_ALERTA_ETIQUETAS[draft.tipo]} en ${zonaTexto(draft)}`}
                        >
                          {publishingId === draft.id ? 'Publicando…' : 'Publicar'}
                        </button>
                      )}
                      {publishError?.draftId === draft.id && (
                        <p role="alert" className="alert error">
                          {publishError.message}
                        </p>
                      )}
                    </>
                  )}
                </li>
              ))}
            </ul>
          ))}
      </section>
    </>
  )
}
