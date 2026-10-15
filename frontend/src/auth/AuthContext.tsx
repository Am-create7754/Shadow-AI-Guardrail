import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { api, setToken, setUnauthorizedHandler } from '../api/client'
import type { User } from '../api/types'
import { AuthContext } from './context'

/**
 * Session state. The token is held in a module variable inside the API client
 * (memory only): a page reload signs the user out, by design, so a token can
 * never be recovered from browser storage by injected script.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const clear = useCallback(
    (message: string | null) => {
      setToken(null)
      setUser(null)
      setNotice(message)
      queryClient.clear()
    },
    [queryClient],
  )

  useEffect(() => {
    setUnauthorizedHandler(() => clear('Your session ended. Please sign in again.'))
    return () => setUnauthorizedHandler(null)
  }, [clear])

  const login = useCallback(async (username: string, password: string) => {
    const { access_token } = await api.login(username, password)
    setToken(access_token)
    try {
      setUser(await api.me())
      setNotice(null)
    } catch (err) {
      setToken(null)
      throw err
    }
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } finally {
      clear(null)
    }
  }, [clear])

  const value = useMemo(() => ({ user, notice, login, logout }), [user, notice, login, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
