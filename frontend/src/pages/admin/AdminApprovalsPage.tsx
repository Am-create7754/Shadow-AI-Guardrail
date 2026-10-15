import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, X } from 'lucide-react'

import { api } from '../../api/client'
import { HighlightedText } from '../../components/guardrail'
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, Label, PageHeader, Select, Spinner } from '../../components/ui'
import { formatTime } from '../../lib/format'
import { StatusBadge } from '../MyApprovalsPage'

export function AdminApprovalsPage() {
  const qc = useQueryClient()
  const [status, setStatus] = useState('pending')
  const [selected, setSelected] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const users = useQuery({ queryKey: ['users'], queryFn: api.users })
  const list = useQuery({ queryKey: ['admin-approvals', status], queryFn: () => api.adminApprovals(status || undefined), refetchInterval: 15_000 })
  const detail = useQuery({ queryKey: ['admin-approval', selected], queryFn: () => api.adminApproval(selected ?? ''), enabled: !!selected })
  const decide = useMutation({
    mutationFn: ({ approve }: { approve: boolean }) => api.decide(selected ?? '', approve, note),
    onSuccess: () => {
      setNote('')
      void qc.invalidateQueries({ queryKey: ['admin-approvals'] })
      void qc.invalidateQueries({ queryKey: ['admin-approval', selected] })
    },
  })
  const nameOf = (id: string | null) => users.data?.find((u) => u.id === id)?.username ?? id ?? '—'
  const a = detail.data

  return (
    <div>
      <PageHeader
        title="Approval queue"
        description="Requests the policy held back. You only ever see the redacted text. You cannot decide requests of your own account, of accounts you created, or of accounts linked to you."
        actions={
          <Select aria-label="Status filter" value={status} onChange={(e) => { setStatus(e.target.value); setSelected(null) }} className="w-40">
            {['pending', 'approved', 'denied', 'executed', 'expired', ''].map((s) => <option key={s} value={s}>{s || 'all'}</option>)}
          </Select>
        }
      />
      <ErrorBanner error={list.error ?? detail.error ?? decide.error} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Card title="Requests">
          {list.isLoading ? <Spinner /> : !list.data?.length ? <EmptyState>Nothing here.</EmptyState> : (
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {list.data.map((r) => (
                <li key={r.id}>
                  <button
                    onClick={() => { setSelected(r.id); decide.reset() }}
                    className={`w-full rounded-lg px-2 py-3 text-left hover:bg-[var(--surface-sunken)] ${selected === r.id ? 'bg-[var(--surface-sunken)]' : ''}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium">{nameOf(r.requester_id)}</span>
                      <StatusBadge status={r.status} />
                    </div>
                    <div className="mt-1 text-xs text-[var(--text-muted)]">{formatTime(r.created_at)} · risk {r.risk_score} · {r.model}</div>
                    <div className="mt-1 truncate text-xs">{r.summary.reasons.join('; ')}</div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Review">
          {!selected ? <EmptyState>Select a request.</EmptyState> : detail.isLoading || !a ? <Spinner /> : (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2 text-xs">
                <StatusBadge status={a.status} />
                {Object.entries(a.summary.entities).map(([k, v]) => <Badge key={k}>{k} ×{v}</Badge>)}
              </div>
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <dt className="text-[var(--text-muted)]">Requester</dt><dd>{nameOf(a.requester_id)}</dd>
                <dt className="text-[var(--text-muted)]">Model</dt><dd className="font-mono text-xs">{a.model}</dd>
                <dt className="text-[var(--text-muted)]">Expires</dt><dd>{formatTime(a.expires_at)}</dd>
                {a.decided_by && <><dt className="text-[var(--text-muted)]">Decided by</dt><dd>{nameOf(a.decided_by)}</dd></>}
              </dl>
              <div>
                <div className="mb-1 text-xs font-medium text-[var(--text-muted)]">Held messages (already redacted)</div>
                {a.messages ? (
                  <div className="space-y-2">
                    {a.messages.map((msg, i) => (
                      <div key={i} className="rounded-lg bg-[var(--surface-sunken)] p-3 text-sm">
                        <div className="mb-1 text-[11px] uppercase text-[var(--text-muted)]">{msg.role}</div>
                        <HighlightedText text={msg.content} className="font-mono" />
                      </div>
                    ))}
                  </div>
                ) : <p className="text-sm text-[var(--text-muted)]">Content erased (request finished or expired).</p>}
              </div>
              {a.status === 'pending' && (
                <div className="space-y-3 border-t pt-4" style={{ borderColor: 'var(--border)' }}>
                  <div>
                    <Label htmlFor="note">Note to the requester (optional)</Label>
                    <Input id="note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
                  </div>
                  <div className="flex gap-2">
                    <Button variant="success" loading={decide.isPending && decide.variables?.approve} onClick={() => decide.mutate({ approve: true })}><Check className="size-4" aria-hidden /> Approve</Button>
                    <Button variant="danger" loading={decide.isPending && !decide.variables?.approve} onClick={() => decide.mutate({ approve: false })}><X className="size-4" aria-hidden /> Deny</Button>
                  </div>
                </div>
              )}
              {a.decision_note && <p className="text-sm"><span className="text-[var(--text-muted)]">Note:</span> {a.decision_note}</p>}
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}
