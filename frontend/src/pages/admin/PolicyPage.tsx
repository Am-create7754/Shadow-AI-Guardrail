import { useQuery } from '@tanstack/react-query'

import { api } from '../../api/client'
import { ActionBadge, Card, ErrorBanner, PageHeader, Spinner } from '../../components/ui'

function ActionTable({ title, actions }: { title: string; actions: Record<string, string> }) {
  const entries = Object.entries(actions)
  return (
    <Card title={title}>
      {!entries.length ? <p className="text-sm text-[var(--text-muted)]">None.</p> : (
        <table className="w-full text-sm">
          <tbody>
            {entries.map(([k, v]) => (
              <tr key={k} className="border-t first:border-t-0" style={{ borderColor: 'var(--border)' }}>
                <td className="py-1.5 font-mono text-xs">{k}</td>
                <td className="py-1.5 text-right"><ActionBadge action={v} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  )
}

export function PolicyPage() {
  const policy = useQuery({ queryKey: ['policy'], queryFn: api.policy })
  const p = policy.data
  return (
    <div>
      <PageHeader
        title="Active policy"
        description="Read-only view of backend/app/policy/default_policy.yaml (or the file configured by GUARDRAIL_POLICY_PATH). Edit the file and restart the gateway to change it."
      />
      <ErrorBanner error={policy.error} />
      {policy.isLoading || !p ? <Spinner /> : (
        <div className="space-y-6">
          <Card title={`Policy "${p.name}"`}>
            <p className="text-sm text-[var(--text-muted)]">{p.description}</p>
            <dl className="mt-3 grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
              <dt className="text-[var(--text-muted)]">Default action</dt><dd><ActionBadge action={p.default_action} /></dd>
              <dt className="text-[var(--text-muted)]">Minimum confidence</dt><dd>{p.min_confidence}</dd>
              <dt className="text-[var(--text-muted)]">Code checks</dt><dd>{p.output.code.mode} (block at {String(p.output.code.block_at)})</dd>
            </dl>
          </Card>
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
            <ActionTable title="Prompts — by category" actions={p.category_actions} />
            <ActionTable title="Prompts — by entity" actions={p.entity_actions} />
            <ActionTable title="Answers — by category" actions={p.output.category_actions} />
            <ActionTable title="Answers — by entity" actions={p.output.entity_actions} />
          </div>
          <Card title="Full policy (JSON)">
            <pre className="max-h-96 overflow-auto font-mono text-xs leading-5">{JSON.stringify(p, null, 2)}</pre>
          </Card>
        </div>
      )}
    </div>
  )
}
