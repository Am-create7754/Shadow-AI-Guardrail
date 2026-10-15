import { useState, type FormEvent } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, ShieldX } from 'lucide-react'

import { api } from '../../api/client'
import type { AuditEvent } from '../../api/types'
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, PageHeader, Spinner } from '../../components/ui'
import { formatTime } from '../../lib/format'

const PAGE = 50

function EventRow({ e, nameOf }: { e: AuditEvent; nameOf: (id: string) => string }) {
  const [open, setOpen] = useState(false)
  const action = typeof e.data.action === 'string' ? e.data.action : null
  return (
    <>
      <tr className="cursor-pointer border-t hover:bg-[var(--surface-sunken)]" style={{ borderColor: 'var(--border)' }} onClick={() => setOpen(!open)}>
        <td className="py-2 pr-3 font-mono text-xs tabular-nums">{e.seq}</td>
        <td className="py-2 pr-3 text-xs">{formatTime(e.recorded_at)}</td>
        <td className="py-2 pr-3 font-mono text-xs">{e.event_type}</td>
        <td className="py-2 pr-3 text-xs">{nameOf(e.actor)}</td>
        <td className="py-2 pr-3">{action && <Badge>{action}</Badge>}</td>
        <td className="py-2 font-mono text-[11px] text-[var(--text-muted)]">{e.hash.slice(0, 12)}…</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6} className="bg-[var(--surface-sunken)] px-3 py-2">
            <pre className="overflow-x-auto font-mono text-xs leading-5">{JSON.stringify({ request_id: e.request_id, data: e.data, prev_hash: e.prev_hash, hash: e.hash, key_id: e.key_id }, null, 2)}</pre>
          </td>
        </tr>
      )}
    </>
  )
}

export function AuditLogPage() {
  const [filters, setFilters] = useState({ event_type: '', actor: '' })
  const [draft, setDraft] = useState(filters)
  const users = useQuery({ queryKey: ['users'], queryFn: api.users })
  const events = useInfiniteQuery({
    queryKey: ['audit', filters],
    queryFn: ({ pageParam }) => api.auditEvents({ limit: PAGE, before_seq: pageParam, ...filters }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length === PAGE ? last[last.length - 1]?.seq : undefined),
  })
  const qc = useQueryClient()
  // Verification is itself audited: refresh the list so the new event shows.
  const verify = useMutation({ mutationFn: api.verifyAudit, onSuccess: () => void qc.invalidateQueries({ queryKey: ['audit'] }) })
  const nameOf = (id: string) => users.data?.find((u) => u.id === id)?.username ?? id
  const rows = events.data?.pages.flat() ?? []

  function apply(e: FormEvent) {
    e.preventDefault()
    setFilters(draft)
  }

  const report = verify.data
  return (
    <div>
      <PageHeader
        title="Audit log"
        description="Every decision is chained with HMAC-SHA256 and checkpointed with Ed25519 signatures. Verification recomputes the whole chain."
        actions={<Button onClick={() => verify.mutate()} loading={verify.isPending}><ShieldCheck className="size-4" aria-hidden /> Verify integrity</Button>}
      />
      <ErrorBanner error={events.error ?? verify.error} />
      {report && (
        <Card className="mb-6">
          <div className="flex items-start gap-3">
            {report.ok ? <ShieldCheck className="size-6 text-[var(--color-allow)]" aria-hidden /> : <ShieldX className="size-6 text-[var(--color-block)]" aria-hidden />}
            <div className="text-sm">
              <div className="font-semibold">{report.ok ? 'Chain intact' : `Tampering detected — first bad event #${report.first_bad_seq ?? '?'}`}</div>
              <div className="text-[var(--text-muted)]">
                {report.events_checked} events, {report.checkpoints_checked} signed checkpoints checked{report.anchor_checked ? ', external anchor checked' : ''}.
              </div>
              {report.issues.length > 0 && (
                <ul className="mt-2 list-disc pl-5">
                  {report.issues.map((i, n) => <li key={n}><span className="font-mono text-xs">{i.kind}</span> {i.seq !== null && `#${i.seq}`} — {i.detail}</li>)}
                </ul>
              )}
            </div>
          </div>
        </Card>
      )}
      <Card>
        <form onSubmit={apply} className="mb-4 flex flex-wrap gap-2">
          <Input aria-label="Event type" placeholder="event type, e.g. chat.blocked" value={draft.event_type} onChange={(e) => setDraft({ ...draft, event_type: e.target.value })} className="max-w-xs" />
          <Input aria-label="Actor id" placeholder="actor id" value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} className="max-w-xs" />
          <Button type="submit" variant="secondary">Filter</Button>
        </form>
        {events.isLoading ? <Spinner /> : !rows.length ? <EmptyState>No events.</EmptyState> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-[var(--text-muted)]">
                <tr><th className="py-2 pr-3 font-medium">#</th><th className="py-2 pr-3 font-medium">Recorded</th><th className="py-2 pr-3 font-medium">Event</th><th className="py-2 pr-3 font-medium">Actor</th><th className="py-2 pr-3 font-medium">Decision</th><th className="py-2 font-medium">Hash</th></tr>
              </thead>
              <tbody>{rows.map((e) => <EventRow key={e.seq} e={e} nameOf={nameOf} />)}</tbody>
            </table>
          </div>
        )}
        {events.hasNextPage && (
          <div className="mt-4 text-center">
            <Button variant="secondary" onClick={() => void events.fetchNextPage()} loading={events.isFetchingNextPage}>Load older events</Button>
          </div>
        )}
      </Card>
    </div>
  )
}
