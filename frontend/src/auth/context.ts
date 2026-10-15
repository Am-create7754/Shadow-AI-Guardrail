import { createContext, useContext } from 'react'

import type { User } from '../api/types'

export interface AuthState {
  user: User | null
  /** Set when the session ended unexpectedly (expired, revoked, deactivated). */
  notice: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthState | null>(null)

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
