import { useState, type FormEvent } from 'react'
import { Shield } from 'lucide-react'

import { useAuth } from '../auth/context'
import { Button, ErrorBanner, Input, Label } from '../components/ui'

export function LoginPage() {
  const { login, notice } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username, password)
    } catch (err) {
      setError(err)
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 rounded-2xl bg-[var(--sidebar)] p-3"><Shield className="size-8 text-blue-400" aria-hidden /></div>
          <h1 className="text-xl font-semibold">Shadow AI Guardrail</h1>
          <p className="mt-1 text-sm text-[var(--text-muted)]">Sign in to the AI security gateway</p>
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-xl border bg-[var(--surface)] p-6 shadow-sm" style={{ borderColor: 'var(--border)' }}>
          {notice && <div className="rounded-lg bg-[var(--surface-sunken)] px-3 py-2 text-sm">{notice}</div>}
          <ErrorBanner error={error} />
          <div>
            <Label htmlFor="username">Username</Label>
            <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <Button type="submit" loading={busy} className="w-full">Sign in</Button>
          <p className="text-center text-xs text-[var(--text-muted)]">Your session is kept in memory only — reloading the page signs you out.</p>
        </form>
      </div>
    </div>
  )
}
