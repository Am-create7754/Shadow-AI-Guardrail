import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import App from './App'
import type { User } from './api/types'
import { AuthContext, type AuthState } from './auth/context'

function renderAt(path: string, user: User | null) {
  // Every API call fails fast: these tests are about routing, not data.
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
  const auth: AuthState = { user, notice: null, login: vi.fn(), logout: vi.fn() }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[path]}>
          <App />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

const base = { is_active: true, created_at: '2026-10-15T00:00:00Z', created_by: null }
const developer = { ...base, id: 'd1', username: 'dev', role: 'developer' } as User
const admin = { ...base, id: 'a1', username: 'root', role: 'admin' } as User

describe('App routing', () => {
  it('shows only the login screen when signed out', () => {
    renderAt('/admin/users', null)
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    expect(screen.queryByText('Users')).toBeNull()
  })

  it('keeps developers out of admin screens and hides admin navigation', () => {
    renderAt('/admin/audit', developer)
    expect(screen.queryByRole('heading', { name: 'Audit log' })).toBeNull()
    expect(screen.queryByRole('link', { name: /audit log/i })).toBeNull()
  })

  it('lets admins open admin screens', async () => {
    renderAt('/admin/audit', admin)
    expect(await screen.findByRole('heading', { name: 'Audit log' })).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: /audit log/i }).length).toBeGreaterThan(0)
  })
})

describe('ErrorBoundary', () => {
  it('contains a crashing page without echoing the error', async () => {
    const { ErrorBoundary } = await import('./components/ErrorBoundary')
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    function Boom(): never {
      throw new Error('secret-ish detail sk_live_example')
    }
    render(<ErrorBoundary><Boom /></ErrorBoundary>)
    expect(screen.getByRole('alert')).toHaveTextContent('This page failed to render.')
    expect(document.body.textContent).not.toContain('sk_live_example')
    expect(JSON.stringify(spy.mock.calls)).not.toContain('sk_live_example')
  })
})
