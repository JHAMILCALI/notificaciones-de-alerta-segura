import { LoginRequestSchema } from '@alertasegura/shared'
import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { useAuth } from './auth-context.ts'
import { loginErrorMessage } from './login-messages.ts'

function redirectTarget(state: unknown): string {
  if (typeof state === 'object' && state !== null && 'from' in state) {
    const from = (state as { from: unknown }).from
    // Solo rutas internas absolutas; evita redirecciones abiertas.
    if (typeof from === 'string' && from.startsWith('/') && !from.startsWith('//')) return from
  }
  return '/panel'
}

export function LoginPage() {
  const { state, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (state.status === 'authenticated') {
    return <Navigate to={redirectTarget(location.state)} replace />
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    const parsed = LoginRequestSchema.safeParse({ email, password })
    if (!parsed.success) {
      setError('Ingresa un correo válido y tu contraseña.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      await login(parsed.data.email, parsed.data.password)
      void navigate(redirectTarget(location.state), { replace: true })
    } catch (caught) {
      setError(loginErrorMessage(caught))
      setPassword('')
      setSubmitting(false)
    }
  }

  return (
    <section className="card narrow" aria-labelledby="login-title">
      <h1 id="login-title">Iniciar sesión</h1>
      <p className="muted">Acceso para personal autorizado (administradores, emisores y auditores).</p>
      <form onSubmit={(event) => void onSubmit(event)} noValidate>
        <div className="field">
          <label htmlFor="login-email">Correo electrónico</label>
          <input
            id="login-email"
            name="email"
            type="email"
            autoComplete="username"
            inputMode="email"
            autoCapitalize="none"
            spellCheck={false}
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={submitting}
          />
        </div>
        <div className="field">
          <label htmlFor="login-password">Contraseña</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={submitting}
          />
        </div>
        <div role="alert" className={error ? 'alert error' : undefined}>
          {error}
        </div>
        <button type="submit" className="primary" disabled={submitting} aria-busy={submitting}>
          {submitting ? 'Ingresando…' : 'Ingresar'}
        </button>
      </form>
    </section>
  )
}
