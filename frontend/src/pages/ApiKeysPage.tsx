import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, KeyRound, Trash2 } from 'lucide-react'

import { api } from '../api/client'
import type { CreatedApiKey } from '../api/types'
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, Label, PageHeader, Spinner } from '../components/ui'
import { formatTime } from '../lib/format'

export function ApiKeysPage() {
  const qc = useQueryClient()
  const keys = useQuery({ queryKey: ['my-keys'], queryFn: api.myKeys })
  const [name, setName] = useState('')
  const [created, setCreated] = useState<CreatedApiKey | null>(null)
  const [copied, setCopied] = useState(false)
  const refresh = () => void qc.invalidateQueries({ queryKey: ['my-keys'] })
  const create = useMutation({
    mutationFn: (n: string) => api.createKey(n),
    onSuccess: (k) => {
      setCreated(k)
      setCopied(false)
      setName('')
      refresh()
    },
  })
  const revoke = useMutation({ mutationFn: (id: string) => api.revokeKey(id), onSuccess: refresh })

  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate(name)
  }

  return (
    <div>
      <PageHeader
        title="API keys"
        description="Keys let scripts and tools (e.g. the OpenAI SDK pointed at this gateway) call the API as you. A key is shown once; only a keyed hash is stored."
      />
      <ErrorBanner error={keys.error ?? create.error ?? revoke.error} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Card title="Create a key">
          <form onSubmit={submit} className="space-y-3">
            <div>
              <Label htmlFor="key-name">Name</Label>
              <Input id="key-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="laptop, ci, notebook…" maxLength={64} required />
            </div>
            <Button type="submit" loading={create.isPending}><KeyRound className="size-4" aria-hidden /> Create key</Button>
          </form>
          {created && (
            <div className="mt-4 rounded-lg border p-3" style={{ borderColor: 'color-mix(in srgb, var(--color-redact) 45%, transparent)' }}>
              <div className="text-xs font-semibold text-[var(--color-redact)]">Copy this key now — it will not be shown again.</div>
              <div className="mt-2 break-all rounded bg-[var(--surface-sunken)] p-2 font-mono text-xs">{created.key}</div>
              <div className="mt-2 flex gap-2">
                <Button variant="secondary" onClick={() => void navigator.clipboard.writeText(created.key).then(() => setCopied(true))}>
                  <Copy className="size-4" aria-hidden /> {copied ? 'Copied' : 'Copy'}
                </Button>
                <Button variant="ghost" onClick={() => setCreated(null)}>Done</Button>
              </div>
            </div>
          )}
        </Card>
        <Card title="Your keys">
          {keys.isLoading ? <Spinner /> : !keys.data?.length ? <EmptyState>No keys yet.</EmptyState> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-[var(--text-muted)]">
                  <tr><th className="py-2 pr-3 font-medium">Name</th><th className="py-2 pr-3 font-medium">Prefix</th><th className="py-2 pr-3 font-medium">Created</th><th className="py-2 pr-3 font-medium">Last used</th><th /></tr>
                </thead>
                <tbody>
                  {keys.data.map((k) => (
                    <tr key={k.id} className="border-t" style={{ borderColor: 'var(--border)' }}>
                      <td className="py-2 pr-3">{k.name}</td>
                      <td className="py-2 pr-3 font-mono text-xs">grk_{k.prefix}_…</td>
                      <td className="py-2 pr-3 text-xs">{formatTime(k.created_at)}</td>
                      <td className="py-2 pr-3 text-xs">{formatTime(k.last_used_at)}</td>
                      <td className="py-2 text-right">
                        {k.revoked_at ? <Badge tone="bad">revoked</Badge> : (
                          <Button variant="ghost" onClick={() => { if (confirm(`Revoke key "${k.name}"? Tools using it will stop working.`)) revoke.mutate(k.id) }}>
                            <Trash2 className="size-4 text-[var(--color-block)]" aria-hidden /> Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
