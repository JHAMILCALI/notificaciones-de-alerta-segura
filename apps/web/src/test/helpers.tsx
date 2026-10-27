import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { vi } from 'vitest'
import { AppRoutes } from '../app/AppRoutes.tsx'
import { AuthProvider } from '../features/auth/AuthProvider.tsx'
import { createApiClient, type ApiClient } from '../lib/api.ts'
import { ApiContext } from '../lib/api-context.ts'

export const USER_ID = '3f2b8c1e-6a44-4f0a-9d57-1c2b3a4d5e6f'

export const adminUser = {
  id: USER_ID,
  email: 'admin@alertasegura.test',
  displayName: 'Admin Prueba',
  role: 'ADMIN' as const,
  permissions: ['users:read', 'audit:read'] as const,
}

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

export function errorResponse(
  statusCode: number,
  code: string,
  message: string,
  headers: Record<string, string> = {},
): Response {
  return jsonResponse(
    { statusCode, code, message },
    { status: statusCode, headers: { 'Content-Type': 'application/json', ...headers } },
  )
}

export type FetchMock = ReturnType<typeof vi.fn<typeof fetch>>

export interface RecordedCall {
  url: string
  method: string
  headers: Headers
  body: string | null
}

export function calls(fetchMock: FetchMock): RecordedCall[] {
  return fetchMock.mock.calls.map(([input, init]) => ({
    url: String(input),
    method: init?.method ?? 'GET',
    headers: new Headers(init?.headers),
    body: typeof init?.body === 'string' ? init.body : null,
  }))
}

export function makeFetch(handler: (call: RecordedCall) => Response | Promise<Response>): FetchMock {
  const mock = vi.fn<typeof fetch>((input, init) => {
    const call: RecordedCall = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : null,
    }
    return Promise.resolve(handler(call))
  })
  return mock
}

export function renderApp(options: { fetchMock: FetchMock; route?: string }): { client: ApiClient } {
  const client = createApiClient({ fetch: options.fetchMock })
  render(
    <ApiContext.Provider value={client}>
      <MemoryRouter initialEntries={[options.route ?? '/']}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    </ApiContext.Provider>,
  )
  return { client }
}
