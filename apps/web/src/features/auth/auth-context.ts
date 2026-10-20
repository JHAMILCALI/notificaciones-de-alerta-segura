import type { SessionUser } from '@alertasegura/shared'
import { createContext, useContext } from 'react'

export type AuthState =
  | { status: 'loading'; user: null }
  | { status: 'anonymous'; user: null }
  | { status: 'authenticated'; user: SessionUser }

export interface AuthContextValue {
  state: AuthState
  login(email: string, password: string): Promise<void>
  logout(): Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (value === null) throw new Error('useAuth debe usarse dentro de <AuthProvider>')
  return value
}
