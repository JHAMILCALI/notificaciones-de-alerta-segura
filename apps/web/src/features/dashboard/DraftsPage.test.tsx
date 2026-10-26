import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { calls, errorResponse, jsonResponse, makeFetch, renderApp, USER_ID } from '../../test/helpers.tsx'

const issuer = {
  id: USER_ID,
  email: 'emisor@alertasegura.test',
  displayName: 'Emisor Prueba',
  role: 'ISSUER',
  permissions: ['drafts:create', 'drafts:read-own', 'alerts:publish', 'alerts:cancel'],
}

const DRAFT_ID = '6c1f9d52-8b0e-4a77-b3a1-0e5d2f9c7a10'
const ALERTA_ID = '0a4c7e19-5d2b-4f83-9c61-7e2b8d3a1f55'

const draft = {
  id: DRAFT_ID,
  tipo: 'LLUVIAS_INTENSAS',
  zona: { departamento: 'COCHABAMBA', municipio: 'Quillacollo' },
  severidad: 'NARANJA',
  mensaje: 'Se esperan lluvias intensas esta noche',
  vigenciaHoras: 12,
  status: 'DRAFT',
  ownerId: USER_ID,
  alertaId: null,
  // 12:00 UTC = 08:00 en La Paz
  createdAt: '2026-10-19T12:00:00.000Z',
  updatedAt: '2026-10-19T12:00:00.000Z',
}

const envelope = {
  payload_canonico: 'e30',
  hash_payload: 'a'.repeat(64),
  firma: 'A'.repeat(86),
  key_id: 'B'.repeat(43),
}

const alertaPublicada = {
  id: ALERTA_ID,
  emisorId: USER_ID,
  publishedAt: '2026-10-19T12:05:00.000Z',
  resumen: {
    tipo: 'LLUVIAS_INTENSAS',
    zona: { departamento: 'COCHABAMBA', municipio: 'Quillacollo' },
    severidad: 'NARANJA',
    mensaje: draft.mensaje,
    emitida_en: '2026-10-19T12:05:00Z',
    expira_en: '2026-10-20T00:05:00Z',
  },
  alerta: envelope,
  eventos: [],
  estado: envelope,
}

function routes(options: { user?: typeof issuer; publish?: () => Response; drafts?: () => unknown[] } = {}) {
  let published = false
  return makeFetch((call) => {
    if (call.url.endsWith('/auth/me')) return jsonResponse({ user: options.user ?? issuer })
    if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'tok-draft' })
    if (call.method === 'POST' && call.url.endsWith('/publish')) {
      const response = options.publish?.() ?? jsonResponse({ alerta: alertaPublicada }, { status: 201 })
      if (response.status === 201) published = true
      return response
    }
    if (call.method === 'POST' && call.url.endsWith('/drafts')) return jsonResponse({ draft }, { status: 201 })
    if (call.url.endsWith('/drafts')) {
      const list = options.drafts?.() ?? [published ? { ...draft, status: 'PUBLISHED', alertaId: ALERTA_ID } : draft]
      return jsonResponse({ drafts: list })
    }
    return errorResponse(404, 'NOT_FOUND', 'No existe')
  })
}

describe('borradores del emisor (D-4, Bolivia)', () => {
  it('crea un borrador con los campos oficiales, X-CSRF-Token y recarga la lista', async () => {
    const user = userEvent.setup({ delay: null })
    let created = false
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: issuer })
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'tok-draft' })
      if (call.method === 'POST' && call.url.endsWith('/drafts')) {
        created = true
        return jsonResponse({ draft }, { status: 201 })
      }
      if (call.url.endsWith('/drafts')) return jsonResponse({ drafts: created ? [draft] : [] })
      return errorResponse(404, 'NOT_FOUND', 'No existe')
    })
    renderApp({ fetchMock, route: '/panel/borradores' })

    expect(await screen.findByText('Todavía no tienes borradores.')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Tipo de alerta'), 'LLUVIAS_INTENSAS')
    await user.selectOptions(screen.getByLabelText('Departamento'), 'COCHABAMBA')
    await user.type(screen.getByLabelText('Municipio (opcional)'), 'Quillacollo')
    await user.selectOptions(screen.getByLabelText('Nivel de alerta'), 'NARANJA')
    await user.click(screen.getByLabelText('Mensaje'))
    await user.paste('Se esperan lluvias intensas esta noche')
    await user.clear(screen.getByLabelText('Vigencia (horas)'))
    await user.type(screen.getByLabelText('Vigencia (horas)'), '12')
    await user.click(screen.getByRole('button', { name: 'Crear borrador' }))

    expect(await screen.findByRole('heading', { name: 'Lluvias intensas' })).toBeInTheDocument()
    const post = calls(fetchMock).find((c) => c.method === 'POST')
    expect(post?.headers.get('X-CSRF-Token')).toBe('tok-draft')
    expect(JSON.parse(post?.body ?? '{}')).toEqual({
      tipo: 'LLUVIAS_INTENSAS',
      zona: { departamento: 'COCHABAMBA', municipio: 'Quillacollo' },
      severidad: 'NARANJA',
      mensaje: 'Se esperan lluvias intensas esta noche',
      vigenciaHoras: 12,
    })
  })

  it('el municipio es opcional: vacío se envía como null', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = routes({ drafts: () => [] })
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.selectOptions(await screen.findByLabelText('Tipo de alerta'), 'HELADA')
    await user.selectOptions(screen.getByLabelText('Departamento'), 'LA_PAZ')
    await user.click(screen.getByLabelText('Mensaje'))
    await user.paste('Helada fuerte en el altiplano')
    await user.click(screen.getByRole('button', { name: 'Crear borrador' }))
    await screen.findByText('Todavía no tienes borradores.')
    const post = calls(fetchMock).find((c) => c.method === 'POST' && c.url.endsWith('/drafts'))
    expect(JSON.parse(post?.body ?? '{}')).toEqual({
      tipo: 'HELADA',
      zona: { departamento: 'LA_PAZ', municipio: null },
      severidad: 'AMARILLA',
      mensaje: 'Helada fuerte en el altiplano',
      vigenciaHoras: 24,
    })
  })

  it('valida antes de llamar a la API: falta tipo y departamento, mensaje corto', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = routes({ drafts: () => [] })
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.type(await screen.findByLabelText('Mensaje'), 'corto')
    await user.click(screen.getByRole('button', { name: 'Crear borrador' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Selecciona el tipo de alerta.')
    expect(alert).toHaveTextContent('Selecciona el departamento.')
    expect(alert).toHaveTextContent('El mensaje debe tener entre 10 y 1000 caracteres.')
    expect(calls(fetchMock).some((c) => c.method === 'POST')).toBe(false)
  })

  it.each(['0', '73', '1.5', ''])('rechaza la vigencia "%s" (solo enteros de 1 a 72 horas)', async (value) => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = routes({ drafts: () => [] })
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.selectOptions(await screen.findByLabelText('Tipo de alerta'), 'HELADA')
    await user.selectOptions(screen.getByLabelText('Departamento'), 'ORURO')
    await user.click(screen.getByLabelText('Mensaje'))
    await user.paste('Helada fuerte en el altiplano')
    await user.clear(screen.getByLabelText('Vigencia (horas)'))
    if (value !== '') await user.type(screen.getByLabelText('Vigencia (horas)'), value)
    await user.click(screen.getByRole('button', { name: 'Crear borrador' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('La vigencia debe ser un número entero de horas entre 1 y 72.')
    expect(calls(fetchMock).some((c) => c.method === 'POST')).toBe(false)
  })

  it('muestra tipo, zona, nivel con su nombre, vigencia y la fecha en hora de Bolivia', async () => {
    renderApp({ fetchMock: routes(), route: '/panel/borradores' })
    const item = (await screen.findByRole('heading', { name: 'Lluvias intensas' })).closest('li')
    expect(item).not.toBeNull()
    const scope = within(item as HTMLElement)
    expect(scope.getByText('Alerta naranja')).toBeInTheDocument()
    expect(scope.getByText(/Quillacollo, Cochabamba/)).toBeInTheDocument()
    expect(scope.getByText(/vigencia 12 h/)).toBeInTheDocument()
    expect(scope.getByText(/8:00/)).toBeInTheDocument()
    expect(scope.getByText('Borrador')).toBeInTheDocument()
  })
})

describe('publicar un borrador', () => {
  it('201: muestra el identificador de la alerta y marca el borrador como publicado', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = routes()
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.click(await screen.findByRole('button', { name: /Publicar borrador de Lluvias intensas/ }))

    expect(await screen.findByText(ALERTA_ID, { selector: 'p.alert code' })).toBeInTheDocument()
    expect(await screen.findByText('Publicada')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Publicar borrador/ })).not.toBeInTheDocument()
    const post = calls(fetchMock).find((c) => c.url.endsWith('/publish'))
    expect(post?.method).toBe('POST')
    expect(post?.url).toBe(`/api/v1/drafts/${DRAFT_ID}/publish`)
    expect(post?.headers.get('X-CSRF-Token')).toBe('tok-draft')
  })

  it('503 SIGNER_UNAVAILABLE: explica que no se publicó nada y permite reintentar', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: routes({ publish: () => errorResponse(503, 'SIGNER_UNAVAILABLE', 'Firmante no disponible') }),
      route: '/panel/borradores',
    })
    await user.click(await screen.findByRole('button', { name: /Publicar borrador/ }))
    expect(await within(await screen.findByRole('listitem')).findByRole('alert')).toHaveTextContent(
      'El servicio de firma no está disponible. No se publicó nada',
    )
    expect(screen.getByText('Borrador')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Publicar borrador/ })).toBeEnabled()
    expect(screen.queryByText('Publicada')).not.toBeInTheDocument()
  })

  it('409: indica que ya estaba publicado y recarga la lista', async () => {
    const user = userEvent.setup({ delay: null })
    let published = false
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: issuer })
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'tok-draft' })
      if (call.url.endsWith('/publish')) {
        published = true
        return errorResponse(409, 'CONFLICT', 'Ya publicado')
      }
      return jsonResponse({ drafts: [published ? { ...draft, status: 'PUBLISHED', alertaId: ALERTA_ID } : draft] })
    })
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.click(await screen.findByRole('button', { name: /Publicar borrador/ }))
    expect(await screen.findByText('Publicada')).toBeInTheDocument()
  })

  it('429: muestra el mensaje de límite de solicitudes', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: routes({ publish: () => errorResponse(429, 'RATE_LIMITED', 'Cuota', { 'Retry-After': '60' }) }),
      route: '/panel/borradores',
    })
    await user.click(await screen.findByRole('button', { name: /Publicar borrador/ }))
    expect(await within(await screen.findByRole('listitem')).findByRole('alert')).toHaveTextContent('Demasiadas solicitudes')
  })

  it('sin el permiso alerts:publish no se ofrece el botón', async () => {
    const reader = { ...issuer, permissions: ['drafts:create', 'drafts:read-own'] }
    renderApp({ fetchMock: routes({ user: reader }), route: '/panel/borradores' })
    await screen.findByRole('heading', { name: 'Lluvias intensas' })
    expect(screen.queryByRole('button', { name: /Publicar borrador/ })).not.toBeInTheDocument()
  })

  it('no se puede publicar dos veces a la vez: el botón queda deshabilitado mientras se firma', async () => {
    const user = userEvent.setup({ delay: null })
    let release: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const fetchMock = makeFetch(async (call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: issuer })
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'tok-draft' })
      if (call.url.endsWith('/publish')) {
        await gate
        return jsonResponse({ alerta: alertaPublicada }, { status: 201 })
      }
      return jsonResponse({ drafts: [draft] })
    })
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.click(await screen.findByRole('button', { name: /Publicar borrador/ }))
    const busy = await screen.findByRole('button', { name: /Publicar borrador/ })
    expect(busy).toBeDisabled()
    expect(busy).toHaveTextContent('Publicando…')
    release?.()
    expect(await screen.findByText(ALERTA_ID, { selector: 'p.alert code' })).toBeInTheDocument()
    expect(calls(fetchMock).filter((c) => c.url.endsWith('/publish'))).toHaveLength(1)
  })
})

describe('cancelar una alerta publicada', () => {
  const publishedDraft = { ...draft, status: 'PUBLISHED', alertaId: ALERTA_ID }

  function cancelRoutes(cancel: () => Response, user = issuer) {
    return makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user })
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'tok-draft' })
      if (call.url.endsWith('/cancel')) return cancel()
      return jsonResponse({ drafts: [publishedDraft] })
    })
  }

  it('pide confirmación, envía POST /alerts/:id/cancel con {} y CSRF, y marca la alerta como cancelada', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = cancelRoutes(() => jsonResponse({ alerta: alertaPublicada }, { status: 201 }))
    renderApp({ fetchMock, route: '/panel/borradores' })

    await user.click(await screen.findByRole('button', { name: /Cancelar la alerta/ }))
    // Todavía no se ha enviado nada: falta confirmar.
    expect(calls(fetchMock).some((c) => c.url.endsWith('/cancel'))).toBe(false)
    expect(screen.getByText(/no se puede deshacer/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Sí, cancelar alerta' }))

    expect(await screen.findByText('Cancelada')).toBeInTheDocument()
    expect(screen.queryByText('Publicada')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Cancelar la alerta/ })).not.toBeInTheDocument()
    const post = calls(fetchMock).find((c) => c.url.endsWith('/cancel'))
    expect(post?.method).toBe('POST')
    expect(post?.url).toBe(`/api/v1/alerts/${ALERTA_ID}/cancel`)
    expect(post?.headers.get('X-CSRF-Token')).toBe('tok-draft')
    expect(post?.body).toBe('{}')
  })

  it('"No, volver" descarta la confirmación sin llamar a la API', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = cancelRoutes(() => jsonResponse({ alerta: alertaPublicada }, { status: 201 }))
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.click(await screen.findByRole('button', { name: /Cancelar la alerta/ }))
    await user.click(screen.getByRole('button', { name: 'No, volver' }))
    expect(screen.getByRole('button', { name: /Cancelar la alerta/ })).toBeInTheDocument()
    expect(calls(fetchMock).some((c) => c.url.endsWith('/cancel'))).toBe(false)
  })

  it('503 SIGNER_UNAVAILABLE: indica que no se canceló y permite reintentar', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: cancelRoutes(() => errorResponse(503, 'SIGNER_UNAVAILABLE', 'Firmante no disponible')),
      route: '/panel/borradores',
    })
    await user.click(await screen.findByRole('button', { name: /Cancelar la alerta/ }))
    await user.click(screen.getByRole('button', { name: 'Sí, cancelar alerta' }))
    expect(await within(await screen.findByRole('listitem')).findByRole('alert')).toHaveTextContent(
      'La alerta no se canceló',
    )
    expect(screen.getByText('Publicada')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sí, cancelar alerta' })).toBeEnabled()
  })

  it('403: solo el emisor puede cancelar', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: cancelRoutes(() => errorResponse(403, 'FORBIDDEN', 'Denegado')),
      route: '/panel/borradores',
    })
    await user.click(await screen.findByRole('button', { name: /Cancelar la alerta/ }))
    await user.click(screen.getByRole('button', { name: 'Sí, cancelar alerta' }))
    expect(await within(await screen.findByRole('listitem')).findByRole('alert')).toHaveTextContent(
      'Solo el emisor de la alerta puede cancelarla.',
    )
  })

  it('409: la alerta ya estaba cancelada y se muestra como cancelada', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: cancelRoutes(() => errorResponse(409, 'CONFLICT', 'Ya cancelada')),
      route: '/panel/borradores',
    })
    await user.click(await screen.findByRole('button', { name: /Cancelar la alerta/ }))
    await user.click(screen.getByRole('button', { name: 'Sí, cancelar alerta' }))
    expect(await screen.findByText('Cancelada')).toBeInTheDocument()
    expect(screen.getByText('Esta alerta ya estaba cancelada.')).toBeInTheDocument()
  })

  it('sin el permiso alerts:cancel no se ofrece el botón', async () => {
    const publisher = { ...issuer, permissions: ['drafts:create', 'drafts:read-own', 'alerts:publish'] }
    renderApp({
      fetchMock: cancelRoutes(() => jsonResponse({ alerta: alertaPublicada }, { status: 201 }), publisher),
      route: '/panel/borradores',
    })
    await screen.findByText('Publicada')
    expect(screen.queryByRole('button', { name: /Cancelar la alerta/ })).not.toBeInTheDocument()
  })
})
