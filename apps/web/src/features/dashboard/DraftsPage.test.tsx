import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { calls, errorResponse, jsonResponse, makeFetch, renderApp, USER_ID } from '../../test/helpers.tsx'

const issuer = {
  id: USER_ID,
  email: 'emisor@alertasegura.test',
  displayName: 'Emisor Prueba',
  role: 'ISSUER',
  permissions: ['drafts:create', 'drafts:read-own', 'alerts:publish'],
}

const draft = {
  id: '6c1f9d52-8b0e-4a77-b3a1-0e5d2f9c7a10',
  title: 'Aviso de lluvias',
  body: 'Se esperan lluvias intensas esta noche',
  severity: 'WARNING',
  status: 'DRAFT',
  ownerId: USER_ID,
  createdAt: '2026-10-19T12:00:00.000Z',
  updatedAt: '2026-10-19T12:00:00.000Z',
}

describe('borradores del emisor', () => {
  it('crea un borrador con X-CSRF-Token y recarga la lista', async () => {
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

    await user.type(screen.getByLabelText('Título'), 'Aviso de lluvias')
    // El mensaje largo se pega: el tecleo carácter a carácter no aporta nada a lo que se verifica.
    await user.click(screen.getByLabelText('Mensaje'))
    await user.paste('Se esperan lluvias intensas esta noche')
    await user.selectOptions(screen.getByLabelText('Severidad'), 'WARNING')
    await user.click(screen.getByRole('button', { name: 'Crear borrador' }))

    expect(await screen.findByRole('heading', { name: 'Aviso de lluvias' })).toBeInTheDocument()
    const post = calls(fetchMock).find((c) => c.method === 'POST')
    expect(post?.headers.get('X-CSRF-Token')).toBe('tok-draft')
    expect(JSON.parse(post?.body ?? '{}')).toEqual({
      title: 'Aviso de lluvias',
      body: 'Se esperan lluvias intensas esta noche',
      severity: 'WARNING',
    })
  })

  it('valida longitudes mínimas antes de llamar a la API', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return jsonResponse({ user: issuer })
      return jsonResponse({ drafts: [] })
    })
    renderApp({ fetchMock, route: '/panel/borradores' })
    await user.type(await screen.findByLabelText('Título'), 'abc')
    await user.click(screen.getByRole('button', { name: 'Crear borrador' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('El título debe tener entre 5 y 140')
    expect(calls(fetchMock).some((c) => c.method === 'POST')).toBe(false)
  })
})
