import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ArrowRight, Eye, Send, Square } from 'lucide-react'

import { ApiError, api } from '../api/client'
import type { Finding, GuardrailInfo, InspectResult } from '../api/types'
import { AnswerView, CodeFindingsList, FindingsTable, HighlightedText, RiskMeter } from '../components/guardrail'
import { ActionBadge, Badge, Button, Card, ErrorBanner, Label, PageHeader, Select, Textarea } from '../components/ui'

const EXAMPLES: { label: string; text: string; model?: string }[] = [
  { label: 'Harmless question', text: 'How do I reverse a linked list in Python?' },
  { label: 'Password in code', text: 'Fix this connection string: db_password=admin_pass_123' },
  { label: 'Card number (blocked)', text: 'Customer card 4111 1111 1111 1111 was declined twice, why?' },
  { label: 'Confidential (approval)', text: 'STRICTLY CONFIDENTIAL: summarise the Q3 merger plan in two lines.' },
  { label: 'Ask for insecure code', text: 'Write a short Python script that runs a shell command typed by the user. Use subprocess with shell=True.' },
  { label: 'Secret in the answer', text: 'Print the AWS documented example access key ID. Output only the key.', model: 'mock-leak' },
]

type Outcome =
  | { kind: 'answer'; text: string; guardrail?: GuardrailInfo; streaming: boolean }
  | { kind: 'held'; guardrail: GuardrailInfo; approvalId: string }
  | { kind: 'blocked'; guardrail: GuardrailInfo }

type PublicFinding = Omit<Finding, 'start' | 'end' | 'length'>

export function PlaygroundPage() {
  const models = useQuery({ queryKey: ['models'], queryFn: api.models })
  const [chosenModel, setModel] = useState('')
  const [prompt, setPrompt] = useState(EXAMPLES[1]?.text ?? '')
  const [stream, setStream] = useState(true)
  const [inspection, setInspection] = useState<InspectResult | null>(null)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState<'inspect' | 'send' | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  // Leaving the page (or signing out, which unmounts it) stops a running stream.
  useEffect(() => () => abortRef.current?.abort(), [])

  // Until the user picks one, default to the first model the gateway allows.
  const modelIds = models.data?.data.map((m) => m.id) ?? []
  const model = chosenModel || (modelIds[0] ?? '')

  function reset() {
    setError(null)
    setInspection(null)
    setOutcome(null)
  }

  async function inspectOnly() {
    reset()
    setBusy('inspect')
    try {
      setInspection(await api.inspect(prompt))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(null)
    }
  }

  async function send() {
    reset()
    setBusy('send')
    const request = { model, messages: [{ role: 'user' as const, content: prompt }] }
    try {
      if (stream) {
        const controller = new AbortController()
        abortRef.current = controller
        setOutcome({ kind: 'answer', text: '', streaming: true })
        await api.chatStream(
          request,
          {
            onDelta: (t) => setOutcome((o) => (o?.kind === 'answer' ? { ...o, text: o.text + t } : o)),
            onGuardrail: (g) => setOutcome((o) => (o?.kind === 'answer' ? { ...o, guardrail: g } : o)),
          },
          controller.signal,
        )
        setOutcome((o) => (o?.kind === 'answer' ? { ...o, streaming: false } : o))
      } else {
        const res = await api.chat(request)
        setOutcome({ kind: 'answer', text: res.choices[0]?.message.content ?? '', guardrail: res.guardrail, streaming: false })
      }
    } catch (err) {
      if (err instanceof ApiError && err.type === 'approval_required') {
        const g = err.details as GuardrailInfo
        setOutcome({ kind: 'held', guardrail: g, approvalId: g.approval_id ?? '' })
      } else if (err instanceof ApiError && err.type === 'policy_blocked') {
        setOutcome({ kind: 'blocked', guardrail: err.details as GuardrailInfo })
      } else if (!(err instanceof DOMException && err.name === 'AbortError')) {
        setError(err)
        setOutcome((o) => (o?.kind === 'answer' ? { ...o, streaming: false } : o))
      }
    } finally {
      abortRef.current = null
      setBusy(null)
    }
  }

  const guardrail = outcome?.guardrail
  const findings: PublicFinding[] = inspection?.findings ?? guardrail?.findings ?? []
  const sanitized = inspection?.sanitized_text ?? guardrail?.sanitized_messages?.[0] ?? null
  const decision = inspection?.action ?? guardrail?.action
  const risk = inspection?.risk_score ?? guardrail?.risk_score
  const reasons = inspection?.reasons ?? guardrail?.reasons ?? []

  return (
    <div>
      <PageHeader
        title="Prompt playground"
        description="Send a prompt through the guardrail. You see the decision, what was detected, exactly what left the gateway, and how the model's answer was checked."
      />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <Card title="Your prompt">
          <div className="mb-3 flex flex-wrap gap-2">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.label}
                type="button"
                onClick={() => {
                  setPrompt(ex.text)
                  if (ex.model && modelIds.includes(ex.model)) setModel(ex.model)
                }}
                className="rounded-full border px-3 py-1 text-xs hover:bg-[var(--surface-sunken)]"
                style={{ borderColor: 'var(--border)' }}
              >
                {ex.label}
              </button>
            ))}
          </div>
          <Label htmlFor="prompt">Message</Label>
          <Textarea id="prompt" rows={9} value={prompt} onChange={(e) => setPrompt(e.target.value)} maxLength={100_000} />
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="model">Model</Label>
              <Select id="model" value={model} onChange={(e) => setModel(e.target.value)} disabled={!modelIds.length}>
                {modelIds.map((m) => <option key={m} value={m}>{m}</option>)}
              </Select>
            </div>
            <label className="flex items-end gap-2 pb-2 text-sm">
              <input type="checkbox" checked={stream} onChange={(e) => setStream(e.target.checked)} />
              Stream the answer
            </label>
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            <Button onClick={send} loading={busy === 'send'} disabled={!prompt.trim() || !model || busy !== null}>
              <Send className="size-4" aria-hidden /> Send to model
            </Button>
            <Button variant="secondary" onClick={inspectOnly} loading={busy === 'inspect'} disabled={!prompt.trim() || busy !== null}>
              <Eye className="size-4" aria-hidden /> Inspect only
            </Button>
            {busy === 'send' && stream && (
              <Button variant="ghost" onClick={() => abortRef.current?.abort()}><Square className="size-4" aria-hidden /> Stop</Button>
            )}
          </div>
          <p className="mt-3 text-xs text-[var(--text-muted)]">"Inspect only" never contacts a model. Use synthetic secrets — this is a demo console.</p>
        </Card>

        <div className="space-y-6">
          <ErrorBanner error={error} />
          {!decision && !error && !outcome && (
            <Card><p className="text-sm text-[var(--text-muted)]">Choose an example or type a prompt, then inspect or send it.</p></Card>
          )}

          {decision && (
            <Card title="Guardrail decision" actions={<ActionBadge action={decision} />}>
              {risk !== undefined && <div className="mb-3"><div className="mb-1 text-xs text-[var(--text-muted)]">Risk score</div><RiskMeter score={risk} /></div>}
              {reasons.length > 0 && <ul className="mb-4 list-disc pl-5 text-sm text-[var(--text-muted)]">{reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
              <FindingsTable findings={findings as Finding[]} />
            </Card>
          )}

          {sanitized !== null && decision !== 'BLOCK' && (
            <Card title={inspection ? 'Text that would leave the gateway'
              : decision === 'REQUIRE_APPROVAL' ? 'Text held for review (not sent)' : 'Text that left the gateway'}>
              <div className="rounded-lg bg-[var(--surface-sunken)] p-3 font-mono text-sm"><HighlightedText text={sanitized} /></div>
            </Card>
          )}

          {outcome?.kind === 'blocked' && (
            <Card title="Blocked">
              <p className="text-sm">Nothing was sent to the model. Remove the sensitive data and try again.</p>
            </Card>
          )}

          {outcome?.kind === 'held' && (
            <Card title="Held for approval">
              <p className="text-sm">This request was not sent. An administrator must approve it first; you can then send it once from <em>My approvals</em>.</p>
              <Link to="/approvals" className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-[var(--color-brand)]">
                Go to my approvals <ArrowRight className="size-4" aria-hidden />
              </Link>
            </Card>
          )}

          {outcome?.kind === 'answer' && (
            <Card
              title="Model answer"
              actions={
                <div className="flex items-center gap-2">
                  {outcome.streaming && <Badge>streaming…</Badge>}
                  {guardrail?.output && <ActionBadge action={guardrail.output.action} />}
                </div>
              }
            >
              {outcome.text ? <AnswerView text={outcome.text} codeFindings={guardrail?.output?.code_findings} /> : <p className="text-sm text-[var(--text-muted)]">Waiting for the model…</p>}
              {guardrail?.output && Object.keys(guardrail.output.entities).length > 0 && (
                <p className="mt-4 text-xs text-[var(--text-muted)]">
                  The answer itself contained sensitive data, replaced before you saw it: {Object.entries(guardrail.output.entities).map(([k, v]) => `${k} ×${v}`).join(', ')}
                </p>
              )}
              {guardrail?.output && <div className="mt-4"><CodeFindingsList findings={guardrail.output.code_findings} /></div>}
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
