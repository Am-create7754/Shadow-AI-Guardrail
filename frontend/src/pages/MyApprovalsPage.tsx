import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Play } from 'lucide-react'

import { api } from '../api/client'
import type { Approval, ChatCompletion } from '../api/types'
import { AnswerView, CodeFindingsList } from '../components/guardrail'
import { Badge, Button, Card, EmptyState, ErrorBanner, PageHeader, Spinner } from '../components/ui'
import { formatTime } from '../lib/format'

export function StatusBadge({ status }: { status: Approval['status'] }) {
  const tone = status === 'approved' ? 'good' : status === 'denied' || status === 'expired' ? 'bad' : status === 'pending' ? 'warn' : 'neutral'
  return <Badge tone={tone}>{status}</Badge>
}

export function MyApprovalsPage() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['my-approvals'], queryFn: api.myApprovals, refetchInterval: 15_000 })
  const [result, setResult] = useState<{ id: string; res: ChatCompletion } | null>(null)
  const execute = useMutation({
    mutationFn: (id: string) => api.executeApproval(id),
    onSuccess: (res, id) => {
      setResult({ id, res })
      void qc.invalidateQueries({ queryKey: ['my-approvals'] })
    },
  })

  return (
    <div>
      <PageHeader
        title="My approval requests"
        description="Prompts the policy held back. Once an administrator approves one, you can send it to the model exactly once before it expires."
      />
      <ErrorBanner error={list.error ?? execute.error} />
      <Card>
        {list.isLoading ? <Spinner /> : !list.data?.length ? <EmptyState>No requests yet.</EmptyState> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-[var(--text-muted)]">
                <tr><th className="py-2 pr-3 font-medium">Requested</th><th className="py-2 pr-3 font-medium">Why held</th><th className="py-2 pr-3 font-medium">Status</th><th className="py-2 pr-3 font-medium">Note</th><th /></tr>
              </thead>
              <tbody>
                {list.data.map((a) => (
                  <tr key={a.id} className="border-t align-top" style={{ borderColor: 'var(--border)' }}>
                    <td className="py-2 pr-3">{formatTime(a.created_at)}<div className="text-xs text-[var(--text-muted)]">expires {formatTime(a.expires_at)}</div></td>
                    <td className="py-2 pr-3 text-xs">{a.summary.reasons.join('; ')}</td>
                    <td className="py-2 pr-3"><StatusBadge status={a.status} /></td>
                    <td className="py-2 pr-3 text-xs text-[var(--text-muted)]">{a.decision_note ?? '—'}</td>
                    <td className="py-2 text-right">
                      {a.status === 'approved' && (
                        <Button variant="success" loading={execute.isPending && execute.variables === a.id} onClick={() => execute.mutate(a.id)}>
                          <Play className="size-4" aria-hidden /> Send now
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
      {result && (
        <Card title="Answer to your approved request" className="mt-6">
          <AnswerView text={result.res.choices[0]?.message.content ?? ''} codeFindings={result.res.guardrail.output?.code_findings} />
          {result.res.guardrail.output && <div className="mt-4"><CodeFindingsList findings={result.res.guardrail.output.code_findings} /></div>}
        </Card>
      )}
    </div>
  )
}
