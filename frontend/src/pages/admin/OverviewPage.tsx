import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { api } from '../../api/client'
import { Card, EmptyState, ErrorBanner, PageHeader, Select, Spinner, Stat } from '../../components/ui'

const COLORS = {
  ALLOW: 'var(--color-allow)',
  REDACT: 'var(--color-redact)',
  REQUIRE_APPROVAL: 'var(--color-approval)',
  BLOCK: 'var(--color-block)',
}
const WINDOWS = [
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
  { hours: 720, label: 'Last 30 days' },
]

function RankList({ items, empty }: { items: [string, number][]; empty: string }) {
  if (!items.length) return <EmptyState>{empty}</EmptyState>
  const max = Math.max(...items.map(([, n]) => n))
  return (
    <ul className="space-y-2">
      {items.map(([name, n]) => (
        <li key={name}>
          <div className="flex justify-between text-sm"><span className="font-mono text-xs">{name}</span><span className="tabular-nums">{n}</span></div>
          <div className="mt-1 h-1.5 rounded-full bg-[var(--surface-sunken)]">
            <div className="h-full rounded-full bg-[var(--color-brand)]" style={{ width: `${(n / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  )
}

export function OverviewPage() {
  const [hours, setHours] = useState(168)
  const metrics = useQuery({ queryKey: ['metrics', hours], queryFn: () => api.metrics(hours), refetchInterval: 60_000 })
  const m = metrics.data

  return (
    <div>
      <PageHeader
        title="Security overview"
        description="Computed from the tamper-evident audit log. Contains metadata only — entity types, rules and decisions, never prompt text."
        actions={
          <Select aria-label="Time window" value={hours} onChange={(e) => setHours(Number(e.target.value))} className="w-44">
            {WINDOWS.map((w) => <option key={w.hours} value={w.hours}>{w.label}</option>)}
          </Select>
        }
      />
      <ErrorBanner error={metrics.error} />
      {metrics.isLoading || !m ? <Spinner /> : (
        <div className="space-y-6">
          {m.truncated && (
            <div role="status" className="rounded-lg bg-[var(--surface-sunken)] px-3 py-2 text-sm">
              This window has more audit events than the overview aggregates; only the most recent ones are counted. Choose a shorter window for exact figures.
            </div>
          )}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="Requests inspected" value={m.requests} hint={`${m.active_users} active user${m.active_users === 1 ? '' : 's'}`} />
            <Stat label="Protected (redacted, held, blocked)" value={`${Math.round(m.protection_rate * 100)}%`} hint={`${m.protected_requests} of ${m.requests}`} tone="var(--color-redact)" />
            <Stat label="Blocked" value={m.actions.BLOCK} tone="var(--color-block)" hint={`${m.actions.REQUIRE_APPROVAL} held for approval`} />
            <Stat label="Answers with leaked data" value={m.output_entities.reduce((s, [, n]) => s + n, 0)} hint={`${m.output_blocked} answers withheld`} />
          </div>

          <Card title="Decisions over time">
            {!m.timeline.length ? <EmptyState>No traffic in this window.</EmptyState> : (
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={m.timeline} margin={{ top: 4, right: 8, bottom: 4, left: -16 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="bucket" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} tickFormatter={(b: string) => (b.length > 10 ? b.slice(11, 16) : b.slice(5))} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
                    <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    {(Object.keys(COLORS) as (keyof typeof COLORS)[]).map((a) => (
                      <Bar key={a} dataKey={a} stackId="a" fill={COLORS[a]} name={a === 'REQUIRE_APPROVAL' ? 'APPROVAL' : a} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Card title="Most detected in prompts"><RankList items={m.top_entities} empty="Nothing detected yet." /></Card>
            <Card title="Detected in model answers"><RankList items={m.output_entities} empty="No leaks in answers." /></Card>
            <Card title="Insecure code patterns"><RankList items={m.code_findings} empty="No code warnings." /></Card>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Card title="Risk distribution">
              <RankList items={Object.entries(m.risk_bands).filter(([, n]) => n > 0) as [string, number][]} empty="No requests." />
            </Card>
            <Card title="Rules that fired"><RankList items={m.top_rules} empty="No rules fired." /></Card>
            <Card title="Operational signals">
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between"><dt>Provider errors</dt><dd className="tabular-nums">{m.provider_errors}</dd></div>
                <div className="flex justify-between"><dt>Inspect-only checks</dt><dd className="tabular-nums">{m.inspections}</dd></div>
                <div className="flex justify-between"><dt>Failed logins</dt><dd className="tabular-nums">{m.failed_logins}</dd></div>
                <div className="flex justify-between"><dt>Audit events in window</dt><dd className="tabular-nums">{m.events}</dd></div>
                {m.models.map(([name, n]) => <div key={name} className="flex justify-between"><dt className="font-mono text-xs">{name}</dt><dd className="tabular-nums">{n}</dd></div>)}
              </dl>
            </Card>
          </div>

          <Card title="AI sites checked by the browser extension">
            <RankList
              items={m.inspection_sources.filter(([s]) => s.startsWith('extension:')).map(([s, n]) => [s.slice('extension:'.length), n] as [string, number])}
              empty="No prompts checked by the extension in this window."
            />
          </Card>
        </div>
      )}
    </div>
  )
}
