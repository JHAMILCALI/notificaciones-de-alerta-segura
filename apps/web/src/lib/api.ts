import {
  API_PREFIX,
  ApiErrorSchema,
  AlertaResponseSchema,
  AuditListResponseSchema,
  CreateDraftRequestSchema,
  CsrfResponseSchema,
  CSRF_HEADER,
  DraftListResponseSchema,
  DraftResponseSchema,
  LoginRequestSchema,
  LoginResponseSchema,
  MeResponseSchema,
  UserListResponseSchema,
  type AlertaPublicada,
  type ApiErrorCode,
  type AuditListResponse,
  type CreateDraftRequest,
  type Draft,
  type LoginRequest,
  type SessionUser,
  type UserSummary,
} from '@alertasegura/shared'

/** Códigos que genera el propio cliente (no vienen de la API). */
export type ClientErrorCode = 'NETWORK_ERROR' | 'INVALID_RESPONSE'

/** Error de cualquier llamada a la API, con el contrato `ApiError` ya interpretado. */
export class ApiError extends Error {
  readonly status: number
  readonly code: ApiErrorCode | ClientErrorCode
  readonly issues: ReadonlyArray<{ path: string; message: string }>
  /** Segundos indicados por la cabecera `Retry-After` (típico en 429). */
  readonly retryAfterSeconds: number | null

  constructor(init: {
    status: number
    code: ApiErrorCode | ClientErrorCode
    message: string
    issues?: ReadonlyArray<{ path: string; message: string }>
    retryAfterSeconds?: number | null
  }) {
    super(init.message)
    this.name = 'ApiError'
    this.status = init.status
    this.code = init.code
    this.issues = init.issues ?? []
    this.retryAfterSeconds = init.retryAfterSeconds ?? null
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}

export interface ApiClientOptions {
  /** Implementación de fetch; por defecto se resuelve `globalThis.fetch` en cada llamada. */
  fetch?: typeof fetch
  /** Prefijo de rutas relativas; por defecto `/api/v1`. */
  baseUrl?: string
}

export interface ApiClient {
  csrf(): Promise<string>
  login(credentials: LoginRequest): Promise<SessionUser>
  logout(): Promise<void>
  me(): Promise<SessionUser>
  listUsers(): Promise<UserSummary[]>
  listDrafts(): Promise<Draft[]>
  createDraft(input: CreateDraftRequest): Promise<Draft>
  /** Firma y publica el borrador (201). 409 si ya estaba publicado; 503 SIGNER_UNAVAILABLE sin efectos. */
  publishDraft(draftId: string): Promise<AlertaPublicada>
  /** Cancela una alerta propia (201): el servidor firma el evento y el nuevo estado. */
  cancelAlert(alertaId: string): Promise<AlertaPublicada>
  listAudit(limit?: number): Promise<AuditListResponse['entries']>
  /** Se invoca cuando una petición autenticada devuelve 401 UNAUTHENTICATED (sesión caducada). */
  onUnauthenticated(listener: () => void): () => void
  /** Solo para diagnóstico y pruebas: indica si hay un token CSRF en memoria. */
  hasCsrfToken(): boolean
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

function parseRetryAfter(header: string | null): number | null {
  if (header === null) return null
  const trimmed = header.trim()
  if (/^\d+$/.test(trimmed)) return Number(trimmed)
  const date = Date.parse(trimmed)
  if (Number.isNaN(date)) return null
  return Math.max(0, Math.ceil((date - Date.now()) / 1000))
}

/** Forma mínima de un esquema Zod (evita depender de `zod` desde la app). */
interface ResponseSchema<T> {
  safeParse(data: unknown): { success: true; data: T } | { success: false }
}

interface RequestOptions<T> {
  method: 'GET' | 'POST'
  path: string
  body?: unknown
  /** Esquema Zod de la respuesta; sin esquema se espera 204/sin cuerpo. */
  schema?: ResponseSchema<T>
}

function parseOrThrow<T>(schema: ResponseSchema<T>, value: unknown): T {
  const parsed = schema.safeParse(value)
  if (!parsed.success) {
    throw new ApiError({ status: 0, code: 'VALIDATION_FAILED', message: 'Los datos enviados no son válidos.' })
  }
  return parsed.data
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const baseUrl = options.baseUrl ?? API_PREFIX
  const doFetch: typeof fetch = (input, init) => (options.fetch ?? globalThis.fetch)(input, init)

  // El token CSRF solo vive en memoria: nunca en localStorage/sessionStorage.
  let csrfToken: string | null = null
  let csrfInFlight: Promise<string> | null = null
  const listeners = new Set<() => void>()

  async function send(
    method: string,
    path: string,
    body: unknown,
    withCsrf: boolean,
  ): Promise<Response> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (withCsrf) headers[CSRF_HEADER] = await getCsrfToken()
    try {
      return await doFetch(`${baseUrl}${path}`, {
        method,
        headers,
        credentials: 'same-origin',
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    } catch {
      throw new ApiError({
        status: 0,
        code: 'NETWORK_ERROR',
        message: 'No se pudo conectar con el servidor.',
      })
    }
  }

  async function toApiError(response: Response): Promise<ApiError> {
    const retryAfterSeconds = parseRetryAfter(response.headers.get('Retry-After'))
    let payload: unknown
    try {
      payload = await response.json()
    } catch {
      payload = undefined
    }
    const parsed = ApiErrorSchema.safeParse(payload)
    if (parsed.success) {
      return new ApiError({
        status: response.status,
        code: parsed.data.code,
        message: parsed.data.message,
        issues: parsed.data.issues,
        retryAfterSeconds,
      })
    }
    return new ApiError({
      status: response.status,
      code: response.status === 429 ? 'RATE_LIMITED' : 'INTERNAL_ERROR',
      message: 'Respuesta de error inesperada del servidor.',
      retryAfterSeconds,
    })
  }

  async function fetchCsrfToken(): Promise<string> {
    const response = await send('GET', '/auth/csrf', undefined, false)
    if (!response.ok) throw await toApiError(response)
    const parsed = CsrfResponseSchema.safeParse(await response.json().catch(() => undefined))
    if (!parsed.success) {
      throw new ApiError({
        status: response.status,
        code: 'INVALID_RESPONSE',
        message: 'La respuesta de /auth/csrf no cumple el contrato.',
      })
    }
    csrfToken = parsed.data.csrfToken
    return csrfToken
  }

  function getCsrfToken(): Promise<string> {
    if (csrfToken !== null) return Promise.resolve(csrfToken)
    // Varias peticiones simultáneas comparten una única consulta a /auth/csrf.
    csrfInFlight ??= fetchCsrfToken().finally(() => {
      csrfInFlight = null
    })
    return csrfInFlight
  }

  async function request<T>(opts: RequestOptions<T>): Promise<T> {
    const unsafe = !SAFE_METHODS.has(opts.method)
    let response = await send(opts.method, opts.path, opts.body, unsafe)

    if (!response.ok && unsafe) {
      const error = await toApiError(response)
      if (error.code === 'CSRF_INVALID') {
        // Token caducado o rotado: se pide uno nuevo y se reintenta una única vez.
        csrfToken = null
        response = await send(opts.method, opts.path, opts.body, true)
      } else {
        return fail(error)
      }
    }

    if (!response.ok) return fail(await toApiError(response))

    if (opts.schema === undefined) return undefined as T
    const parsed = opts.schema.safeParse(await response.json().catch(() => undefined))
    if (!parsed.success) {
      throw new ApiError({
        status: response.status,
        code: 'INVALID_RESPONSE',
        message: 'La respuesta del servidor no cumple el contrato esperado.',
      })
    }
    return parsed.data
  }

  function fail(error: ApiError): never {
    throw error
  }

  // Los 401 de la rama de reintento también deben notificarse: se envuelve `request`.
  async function guarded<T>(opts: RequestOptions<T>): Promise<T> {
    try {
      return await request(opts)
    } catch (error) {
      if (isApiError(error) && error.status === 401 && error.code === 'UNAUTHENTICATED') {
        for (const listener of listeners) listener()
      }
      throw error
    }
  }

  return {
    async csrf() {
      csrfToken = null
      return getCsrfToken()
    },

    async login(credentials) {
      const body = parseOrThrow(LoginRequestSchema, credentials)
      // El login exige CSRF (también anónimo): `request` obtiene el token si falta.
      const result = await request({
        method: 'POST',
        path: '/auth/login',
        body,
        schema: LoginResponseSchema,
      })
      csrfToken = result.csrfToken
      return result.user
    },

    async logout() {
      try {
        await request({ method: 'POST', path: '/auth/logout' })
      } finally {
        // Tras el logout el token anterior deja de valer: se descarta y se pide uno nuevo.
        csrfToken = null
        await getCsrfToken().catch(() => undefined)
      }
    },

    async me() {
      return (await guarded({ method: 'GET', path: '/auth/me', schema: MeResponseSchema })).user
    },

    async listUsers() {
      return (await guarded({ method: 'GET', path: '/admin/users', schema: UserListResponseSchema })).users
    },

    async listDrafts() {
      return (await guarded({ method: 'GET', path: '/drafts', schema: DraftListResponseSchema })).drafts
    },

    async createDraft(input) {
      const body = parseOrThrow(CreateDraftRequestSchema, input)
      return (
        await guarded({ method: 'POST', path: '/drafts', body, schema: DraftResponseSchema })
      ).draft
    },

    async publishDraft(draftId) {
      const path = `/drafts/${encodeURIComponent(draftId)}/publish`
      return (await guarded({ method: 'POST', path, schema: AlertaResponseSchema })).alerta
    },

    async cancelAlert(alertaId) {
      const path = `/alerts/${encodeURIComponent(alertaId)}/cancel`
      return (await guarded({ method: 'POST', path, body: {}, schema: AlertaResponseSchema })).alerta
    },

    async listAudit(limit) {
      const query = limit === undefined ? '' : `?limit=${encodeURIComponent(String(limit))}`
      return (
        await guarded({ method: 'GET', path: `/audit${query}`, schema: AuditListResponseSchema })
      ).entries
    },

    onUnauthenticated(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },

    hasCsrfToken() {
      return csrfToken !== null
    },
  }
}

/** Cliente de la aplicación (rutas relativas, mismo origen). */
export const api: ApiClient = createApiClient()
