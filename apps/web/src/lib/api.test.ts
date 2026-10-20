import { describe, expect, it } from 'vitest'
import { ApiError, createApiClient } from './api.ts'
import { adminUser, calls, errorResponse, jsonResponse, makeFetch } from '../test/helpers.tsx'

const draft = {
  id: '6c1f9d52-8b0e-4a77-b3a1-0e5d2f9c7a10',
  title: 'Aviso de prueba',
  body: 'Cuerpo del borrador de prueba',
  severity: 'INFO',
  status: 'DRAFT',
  ownerId: adminUser.id,
  createdAt: '2026-10-19T12:00:00.000Z',
  updatedAt: '2026-10-19T12:00:00.000Z',
}

describe('cliente API: CSRF', () => {
  it('obtiene el token de /auth/csrf y lo envía en X-CSRF-Token en el POST', async () => {
    const fetchMock = makeFetch((call) => {
      if (call.url === '/api/v1/auth/csrf') return jsonResponse({ csrfToken: 'tok-1' })
      return jsonResponse({ draft }, { status: 201 })
    })
    const client = createApiClient({ fetch: fetchMock })

    await client.createDraft({ title: 'Aviso de prueba', body: 'Cuerpo del borrador de prueba', severity: 'INFO' })

    const recorded = calls(fetchMock)
    expect(recorded.map((c) => `${c.method} ${c.url}`)).toEqual(['GET /api/v1/auth/csrf', 'POST /api/v1/drafts'])
    expect(recorded[1]?.headers.get('X-CSRF-Token')).toBe('tok-1')
    expect(recorded[1]?.headers.get('Content-Type')).toBe('application/json')
    // GET no lleva token CSRF
    expect(recorded[0]?.headers.get('X-CSRF-Token')).toBeNull()
    // credenciales de mismo origen y rutas relativas
    expect(fetchMock.mock.calls[1]?.[1]?.credentials).toBe('same-origin')
  })

  it('reutiliza el token en memoria (una sola consulta a /auth/csrf)', async () => {
    const fetchMock = makeFetch((call) =>
      call.url.endsWith('/auth/csrf') ? jsonResponse({ csrfToken: 'tok-1' }) : jsonResponse({ draft }, { status: 201 }),
    )
    const client = createApiClient({ fetch: fetchMock })
    const input = { title: 'Aviso de prueba', body: 'Cuerpo del borrador de prueba', severity: 'INFO' } as const
    await client.createDraft(input)
    await client.createDraft(input)
    expect(calls(fetchMock).filter((c) => c.url.endsWith('/auth/csrf'))).toHaveLength(1)
  })

  it('reintenta una vez tras CSRF_INVALID con un token nuevo', async () => {
    let csrfIssued = 0
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: `tok-${++csrfIssued}` })
      if (call.headers.get('X-CSRF-Token') === 'tok-1') {
        return errorResponse(403, 'CSRF_INVALID', 'Token CSRF no válido')
      }
      return jsonResponse({ draft }, { status: 201 })
    })
    const client = createApiClient({ fetch: fetchMock })

    const created = await client.createDraft({
      title: 'Aviso de prueba',
      body: 'Cuerpo del borrador de prueba',
      severity: 'INFO',
    })

    expect(created.id).toBe(draft.id)
    const recorded = calls(fetchMock)
    expect(recorded.map((c) => `${c.method} ${c.url} ${c.headers.get('X-CSRF-Token') ?? '-'}`)).toEqual([
      'GET /api/v1/auth/csrf -',
      'POST /api/v1/drafts tok-1',
      'GET /api/v1/auth/csrf -',
      'POST /api/v1/drafts tok-2',
    ])
  })

  it('no reintenta más de una vez si el segundo intento también devuelve CSRF_INVALID', async () => {
    let n = 0
    const fetchMock = makeFetch((call) =>
      call.url.endsWith('/auth/csrf')
        ? jsonResponse({ csrfToken: `tok-${++n}` })
        : errorResponse(403, 'CSRF_INVALID', 'Token CSRF no válido'),
    )
    const client = createApiClient({ fetch: fetchMock })
    const failure = await client
      .createDraft({ title: 'Aviso de prueba', body: 'Cuerpo del borrador de prueba', severity: 'INFO' })
      .catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).code).toBe('CSRF_INVALID')
    expect(calls(fetchMock).filter((c) => c.method === 'POST')).toHaveLength(2)
  })

  it('el login guarda el csrfToken devuelto y lo usa en el logout; después pide uno nuevo', async () => {
    let csrfCalls = 0
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: `anon-${++csrfCalls}` })
      if (call.url.endsWith('/auth/login')) return jsonResponse({ user: adminUser, csrfToken: 'session-tok' })
      return new Response(null, { status: 204 })
    })
    const client = createApiClient({ fetch: fetchMock })

    await client.login({ email: 'admin@alertasegura.test', password: 'secreto-largo-123' })
    await client.logout()

    const recorded = calls(fetchMock).map((c) => `${c.method} ${c.url} ${c.headers.get('X-CSRF-Token') ?? '-'}`)
    expect(recorded).toEqual([
      'GET /api/v1/auth/csrf -', // el login también exige CSRF
      'POST /api/v1/auth/login anon-1',
      'POST /api/v1/auth/logout session-tok',
      'GET /api/v1/auth/csrf -', // token nuevo tras el logout
    ])
    expect(client.hasCsrfToken()).toBe(true)
  })

  it('no guarda tokens en localStorage ni sessionStorage', async () => {
    const fetchMock = makeFetch((call) =>
      call.url.endsWith('/auth/csrf') ? jsonResponse({ csrfToken: 'tok-x' }) : jsonResponse({ draft }, { status: 201 }),
    )
    const client = createApiClient({ fetch: fetchMock })
    await client.createDraft({ title: 'Aviso de prueba', body: 'Cuerpo del borrador de prueba', severity: 'INFO' })
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })
})

describe('cliente API: errores y contrato', () => {
  it('convierte el cuerpo ApiError y Retry-After en ApiError', async () => {
    const fetchMock = makeFetch(() => errorResponse(429, 'RATE_LIMITED', 'Demasiadas solicitudes', { 'Retry-After': '42' }))
    const client = createApiClient({ fetch: fetchMock })
    const failure = (await client.me().catch((e: unknown) => e)) as ApiError
    expect(failure).toBeInstanceOf(ApiError)
    expect(failure.status).toBe(429)
    expect(failure.code).toBe('RATE_LIMITED')
    expect(failure.retryAfterSeconds).toBe(42)
  })

  it('un cuerpo de error ajeno al contrato se trata como INTERNAL_ERROR', async () => {
    const fetchMock = makeFetch(() => new Response('<html>boom</html>', { status: 502 }))
    const client = createApiClient({ fetch: fetchMock })
    const failure = (await client.me().catch((e: unknown) => e)) as ApiError
    expect(failure.code).toBe('INTERNAL_ERROR')
    expect(failure.status).toBe(502)
  })

  it('rechaza respuestas 200 que no cumplen el esquema de shared', async () => {
    const fetchMock = makeFetch(() => jsonResponse({ user: { id: 'no-es-uuid' } }))
    const client = createApiClient({ fetch: fetchMock })
    const failure = (await client.me().catch((e: unknown) => e)) as ApiError
    expect(failure.code).toBe('INVALID_RESPONSE')
  })

  it('un fallo de red produce NETWORK_ERROR', async () => {
    const fetchMock = makeFetch(() => {
      throw new TypeError('Failed to fetch')
    })
    const client = createApiClient({ fetch: fetchMock })
    const failure = (await client.me().catch((e: unknown) => e)) as ApiError
    expect(failure.code).toBe('NETWORK_ERROR')
  })

  it('notifica a los oyentes ante 401 UNAUTHENTICATED en rutas protegidas', async () => {
    const fetchMock = makeFetch(() => errorResponse(401, 'UNAUTHENTICATED', 'Sesión requerida'))
    const client = createApiClient({ fetch: fetchMock })
    let notified = 0
    client.onUnauthenticated(() => {
      notified++
    })
    await client.listUsers().catch(() => undefined)
    expect(notified).toBe(1)
  })

  it('valida la respuesta de listados con los esquemas de shared', async () => {
    const fetchMock = makeFetch(() =>
      jsonResponse({
        users: [
          {
            id: adminUser.id,
            email: adminUser.email,
            displayName: adminUser.displayName,
            role: 'ADMIN',
            status: 'ACTIVE',
            createdAt: '2026-10-19T12:00:00.000Z',
          },
        ],
      }),
    )
    const client = createApiClient({ fetch: fetchMock })
    const users = await client.listUsers()
    expect(users).toHaveLength(1)
    expect(calls(fetchMock)[0]?.url).toBe('/api/v1/admin/users')
  })
})
