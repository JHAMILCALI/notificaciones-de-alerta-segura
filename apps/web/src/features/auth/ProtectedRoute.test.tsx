import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { adminUser, calls, errorResponse, jsonResponse, makeFetch, renderApp, USER_ID } from '../../test/helpers.tsx'

const issuerUser = {
  id: USER_ID,
  email: 'emisor@alertasegura.test',
  displayName: 'Emisor Prueba',
  role: 'ISSUER' as const,
  permissions: ['drafts:create', 'drafts:read-own', 'alerts:publish'] as const,
}

describe('ruta protegida /panel', () => {
  it('redirige a /login cuando /auth/me devuelve 401', async () => {
    const fetchMock = makeFetch(() => errorResponse(401, 'UNAUTHENTICATED', 'Sesión requerida'))
    renderApp({ fetchMock, route: '/panel' })

    expect(await screen.findByRole('heading', { name: 'Iniciar sesión' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Panel' })).not.toBeInTheDocument()
    expect(calls(fetchMock).map((c) => c.url)).toEqual(['/api/v1/auth/me'])
  })

  it('una subruta protegida también redirige a /login', async () => {
    const fetchMock = makeFetch(() => errorResponse(401, 'UNAUTHENTICATED', 'Sesión requerida'))
    renderApp({ fetchMock, route: '/panel/usuarios' })
    expect(await screen.findByRole('heading', { name: 'Iniciar sesión' })).toBeInTheDocument()
  })

  it('muestra "comprobando sesión" mientras /auth/me está pendiente', () => {
    const fetchMock = makeFetch(() => new Promise<Response>(() => undefined))
    renderApp({ fetchMock, route: '/panel' })
    expect(screen.getByText('Comprobando sesión…')).toBeInTheDocument()
  })

  it('con sesión válida muestra el panel', async () => {
    const fetchMock = makeFetch(() => jsonResponse({ user: adminUser }))
    renderApp({ fetchMock, route: '/panel' })
    expect(await screen.findByRole('heading', { name: 'Panel' })).toBeInTheDocument()
  })

  it('un emisor ve borradores pero no usuarios ni auditoría; la ruta sin permiso informa acceso no permitido', async () => {
    const fetchMock = makeFetch(() => jsonResponse({ user: issuerUser }))
    renderApp({ fetchMock, route: '/panel' })

    expect(await screen.findByRole('link', { name: 'Borradores' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Usuarios' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Auditoría' })).not.toBeInTheDocument()
  })

  it('un emisor que abre /panel/usuarios ve "Acceso no permitido" y no se llama a la API de usuarios', async () => {
    const fetchMock = makeFetch(() => jsonResponse({ user: issuerUser }))
    renderApp({ fetchMock, route: '/panel/usuarios' })
    expect(await screen.findByRole('heading', { name: 'Acceso no permitido' })).toBeInTheDocument()
    expect(calls(fetchMock).some((c) => c.url.endsWith('/admin/users'))).toBe(false)
  })

  it('el administrador lista usuarios desde GET /admin/users', async () => {
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: adminUser })
      return jsonResponse({
        users: [
          {
            id: USER_ID,
            email: 'emisor@alertasegura.test',
            displayName: 'Emisor Prueba',
            role: 'ISSUER',
            status: 'ACTIVE',
            createdAt: '2026-10-19T12:00:00.000Z',
          },
        ],
      })
    })
    renderApp({ fetchMock, route: '/panel/usuarios' })
    expect(await screen.findByText('emisor@alertasegura.test')).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Rol' })).toBeInTheDocument()
  })

  it('logout: vuelve a anónimo, envía X-CSRF-Token y pide un token nuevo', async () => {
    const user = userEvent.setup({ delay: null })
    let csrfCalls = 0
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: adminUser })
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: `tok-${++csrfCalls}` })
      return new Response(null, { status: 204 })
    })
    renderApp({ fetchMock, route: '/panel' })

    await user.click(await screen.findByRole('button', { name: 'Salir' }))

    expect(await screen.findByRole('heading', { name: 'Iniciar sesión' })).toBeInTheDocument()
    const recorded = calls(fetchMock)
    const logout = recorded.find((c) => c.url.endsWith('/auth/logout'))
    expect(logout?.method).toBe('POST')
    expect(logout?.headers.get('X-CSRF-Token')).toBe('tok-1')
    expect(csrfCalls).toBe(2)
  })

  it('una sesión caducada durante el uso (401 en una petición) devuelve al login', async () => {
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: adminUser })
      return errorResponse(401, 'UNAUTHENTICATED', 'Sesión requerida')
    })
    renderApp({ fetchMock, route: '/panel/usuarios' })
    expect(await screen.findByRole('heading', { name: 'Iniciar sesión' })).toBeInTheDocument()
  })
})
