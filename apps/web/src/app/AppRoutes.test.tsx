import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { errorResponse, jsonResponse, makeFetch, renderApp, USER_ID } from '../test/helpers.tsx'

const issuer = {
  id: USER_ID,
  email: 'emisor@alertasegura.test',
  displayName: 'Emisor Prueba',
  role: 'ISSUER',
  permissions: ['drafts:create', 'drafts:read-own', 'alerts:publish', 'alerts:cancel'],
}

function fetchFor(user: typeof issuer | null) {
  return makeFetch((call) => {
    if (call.url.endsWith('/auth/me')) {
      return user === null ? errorResponse(401, 'UNAUTHENTICATED', 'Sin sesión') : jsonResponse({ user })
    }
    if (call.url.endsWith('/drafts')) return jsonResponse({ drafts: [] })
    return errorResponse(404, 'NOT_FOUND', 'No existe')
  })
}

describe('rutas de la PWA (D-3)', () => {
  it('/ redirige a /alertas (consulta ciudadana, sin sesión)', async () => {
    renderApp({ fetchMock: fetchFor(null), route: '/' })
    expect(await screen.findByRole('heading', { name: 'Consulta ciudadana' })).toBeInTheDocument()
  })

  it('/alertas muestra la consulta ciudadana sin pedir sesión', async () => {
    renderApp({ fetchMock: fetchFor(null), route: '/alertas' })
    expect(await screen.findByRole('heading', { name: 'Consulta ciudadana' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Iniciar sesión' })).not.toBeInTheDocument()
  })

  it('/admin sin sesión lleva a iniciar sesión', async () => {
    renderApp({ fetchMock: fetchFor(null), route: '/admin' })
    expect(await screen.findByRole('heading', { name: 'Iniciar sesión' })).toBeInTheDocument()
  })

  it('/admin con sesión muestra el panel', async () => {
    renderApp({ fetchMock: fetchFor(issuer), route: '/admin' })
    expect(await screen.findByRole('heading', { name: 'Panel' })).toBeInTheDocument()
  })

  it('/panel redirige a /admin', async () => {
    renderApp({ fetchMock: fetchFor(issuer), route: '/panel' })
    expect(await screen.findByRole('heading', { name: 'Panel' })).toBeInTheDocument()
  })

  it('/panel/borradores redirige conservando el subpath a /admin/borradores', async () => {
    renderApp({ fetchMock: fetchFor(issuer), route: '/panel/borradores' })
    expect(await screen.findByRole('heading', { name: 'Nuevo borrador' })).toBeInTheDocument()
  })

  it('/panel/borradores sin sesión también termina en iniciar sesión', async () => {
    renderApp({ fetchMock: fetchFor(null), route: '/panel/borradores' })
    expect(await screen.findByRole('heading', { name: 'Iniciar sesión' })).toBeInTheDocument()
  })

  it('una ruta inexistente muestra la página 404 con enlace a las alertas', async () => {
    renderApp({ fetchMock: fetchFor(null), route: '/no-existe' })
    expect(await screen.findByRole('link', { name: 'Volver a las alertas' })).toHaveAttribute('href', '/alertas')
  })

  it('el menú apunta a /alertas y, con sesión, a /admin', async () => {
    renderApp({ fetchMock: fetchFor(issuer), route: '/alertas' })
    expect(await screen.findByRole('link', { name: 'Panel' })).toHaveAttribute('href', '/admin')
    expect(screen.getByRole('link', { name: 'Alertas' })).toHaveAttribute('href', '/alertas')
  })
})
