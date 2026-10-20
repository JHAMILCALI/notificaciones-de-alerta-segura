import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { adminUser, calls, errorResponse, jsonResponse, makeFetch, renderApp } from '../../test/helpers.tsx'

function loginHandler(loginResponse: () => Response) {
  return makeFetch((call) => {
    if (call.url.endsWith('/auth/me')) return errorResponse(401, 'UNAUTHENTICATED', 'Sesión requerida')
    if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'anon-token' })
    if (call.url.endsWith('/auth/login')) return loginResponse()
    return errorResponse(404, 'NOT_FOUND', 'No existe')
  })
}

async function fillAndSubmit(user: ReturnType<typeof userEvent.setup>, email = 'Admin@AlertaSegura.test', password = 'clave-larga-123') {
  await user.type(await screen.findByLabelText('Correo electrónico'), email)
  await user.type(screen.getByLabelText('Contraseña'), password)
  await user.click(screen.getByRole('button', { name: 'Ingresar' }))
}

describe('formulario de login', () => {
  it('tiene etiquetas y autocomplete correctos', async () => {
    renderApp({ fetchMock: loginHandler(() => errorResponse(401, 'INVALID_CREDENTIALS', 'x')), route: '/login' })
    const email = await screen.findByLabelText('Correo electrónico')
    expect(email).toHaveAttribute('autocomplete', 'username')
    expect(email).toHaveAttribute('type', 'email')
    expect(screen.getByLabelText('Contraseña')).toHaveAttribute('autocomplete', 'current-password')
  })

  it('éxito: envía CSRF, entra al panel y muestra usuario, rol y permisos', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = loginHandler(() => jsonResponse({ user: adminUser, csrfToken: 'session-token' }))
    renderApp({ fetchMock, route: '/login' })

    await fillAndSubmit(user)

    expect(await screen.findByRole('heading', { name: 'Panel' })).toBeInTheDocument()
    expect(screen.getByText('Admin Prueba')).toBeInTheDocument()
    expect(screen.getByText('Administrador')).toBeInTheDocument()
    expect(screen.getByText('users:read')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Usuarios' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Auditoría' })).toBeInTheDocument()
    // un ADMIN no tiene drafts:read-own
    expect(screen.queryByRole('link', { name: 'Borradores' })).not.toBeInTheDocument()

    const login = calls(fetchMock).find((c) => c.url.endsWith('/auth/login'))
    expect(login?.method).toBe('POST')
    expect(login?.headers.get('X-CSRF-Token')).toBe('anon-token')
    // el correo se normaliza (trim + minúsculas) por el esquema compartido
    expect(JSON.parse(login?.body ?? '{}')).toEqual({ email: 'admin@alertasegura.test', password: 'clave-larga-123' })
  })

  it('401: mensaje genérico, limpia la contraseña y no revela si la cuenta existe', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: loginHandler(() => errorResponse(401, 'INVALID_CREDENTIALS', 'Credenciales inválidas')),
      route: '/login',
    })

    await fillAndSubmit(user)

    expect(await screen.findByRole('alert')).toHaveTextContent('Correo o contraseña incorrectos.')
    expect(screen.getByLabelText('Contraseña')).toHaveValue('')
    expect(screen.getByLabelText('Correo electrónico')).toHaveValue('Admin@AlertaSegura.test')
    expect(screen.getByRole('button', { name: 'Ingresar' })).toBeEnabled()
  })

  it('429: mensaje claro con el tiempo de Retry-After', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: loginHandler(() =>
        errorResponse(429, 'RATE_LIMITED', 'Demasiadas solicitudes', { 'Retry-After': '90' }),
      ),
      route: '/login',
    })

    await fillAndSubmit(user)

    expect(await screen.findByRole('alert')).toHaveTextContent('Demasiados intentos. Vuelve a intentarlo en 2 minutos.')
  })

  it('429 con pocos segundos indica segundos', async () => {
    const user = userEvent.setup({ delay: null })
    renderApp({
      fetchMock: loginHandler(() => errorResponse(429, 'RATE_LIMITED', 'x', { 'Retry-After': '30' })),
      route: '/login',
    })
    await fillAndSubmit(user)
    expect(await screen.findByRole('alert')).toHaveTextContent('en 30 segundos')
  })

  it('deshabilita el botón mientras se envía', async () => {
    const user = userEvent.setup({ delay: null })
    let release: (response: Response) => void = () => undefined
    const pending = new Promise<Response>((resolve) => {
      release = resolve
    })
    const fetchMock = makeFetch((call) => {
      if (call.url.endsWith('/auth/me')) return errorResponse(401, 'UNAUTHENTICATED', 'Sesión requerida')
      if (call.url.endsWith('/auth/csrf')) return jsonResponse({ csrfToken: 'anon-token' })
      return pending
    })
    renderApp({ fetchMock, route: '/login' })

    await fillAndSubmit(user)

    const button = await screen.findByRole('button', { name: 'Ingresando…' })
    expect(button).toBeDisabled()
    release(errorResponse(401, 'INVALID_CREDENTIALS', 'x'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Ingresar' })).toBeEnabled())
  })

  it('valida en cliente un correo mal formado sin llamar a la API de login', async () => {
    const user = userEvent.setup({ delay: null })
    const fetchMock = loginHandler(() => jsonResponse({ user: adminUser, csrfToken: 't' }))
    renderApp({ fetchMock, route: '/login' })

    await fillAndSubmit(user, 'no-es-correo', 'algo')

    expect(await screen.findByRole('alert')).toHaveTextContent('Ingresa un correo válido')
    expect(calls(fetchMock).some((c) => c.url.endsWith('/auth/login'))).toBe(false)
  })
})
