// Components that visualise guardrail decisions. Model output and user text are
// always rendered as React text nodes (never as HTML), so an answer containing
// <script> or markdown-link tricks is displayed, not executed.

import { Fragment } from 'react'
import { ShieldAlert, ShieldCheck } from 'lucide-react'

import type { CodeFinding, Finding } from '../api/types'
import { cx, splitFences } from '../lib/format'
import { ActionBadge, Badge, SeverityText } from './ui'

const PLACEHOLDER = /(\[[A-Z][A-Z0-9_]*_\d{1,6}\])/g

/** Plain text with [ENTITY_N] placeholders highlighted. */
export function HighlightedText({ text, className }: { text: string; className?: string }) {
  const parts = text.split(PLACEHOLDER)
  return (
    <span className={cx('whitespace-pre-wrap break-words', className)}>
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <span key={i} className="placeholder-token" title="Redacted by the guardrail">{part}</span>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </span>
  )
}

export function AnswerView({ text, codeFindings = [] }: { text: string; codeFindings?: CodeFinding[] }) {
  // Number code blocks up front (render must not mutate locals across map calls).
  const segments = splitFences(text)
  const blockIndex = segments.map((_, i) => segments.slice(0, i).filter((s) => s.kind === 'code').length)
  return (
    <div className="space-y-3 text-sm leading-relaxed">
      {segments.map((seg, i) => {
        if (seg.kind === 'text') return <p key={i}><HighlightedText text={seg.content} /></p>
        const block = blockIndex[i]
        const flagged = new Set(codeFindings.filter((f) => f.block === block).map((f) => f.line))
        return (
          <div key={i} className="overflow-hidden rounded-lg border" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between bg-[var(--surface-sunken)] px-3 py-1 text-xs text-[var(--text-muted)]">
              <span>{seg.language || 'code'}</span>
              {flagged.size > 0 && <Badge tone="bad">{flagged.size} flagged line{flagged.size > 1 ? 's' : ''}</Badge>}
            </div>
            <pre className="overflow-x-auto p-3 font-mono text-xs leading-5">
              {seg.content.split('\n').map((line, n) => (
                <div key={n} className={cx(flagged.has(n + 1) && 'bg-[color-mix(in_srgb,var(--color-block)_14%,transparent)]')}>
                  <span className="mr-3 inline-block w-6 select-none text-right text-[var(--text-muted)]">{n + 1}</span>
                  <HighlightedText text={line} />
                </div>
              ))}
            </pre>
          </div>
        )
      })}
    </div>
  )
}

export function RiskMeter({ score }: { score: number }) {
  const color = score >= 85 ? 'var(--color-block)' : score >= 60 ? 'var(--color-block)' : score >= 30 ? 'var(--color-redact)' : score > 0 ? 'var(--color-brand)' : 'var(--color-allow)'
  return (
    <div className="flex items-center gap-3" aria-label={`risk score ${score} of 100`}>
      <div className="h-2 w-32 overflow-hidden rounded-full bg-[var(--surface-sunken)]">
        <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(score, 2)}%`, background: color }} />
      </div>
      <span className="text-sm font-semibold tabular-nums" style={{ color }}>{score}</span>
    </div>
  )
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return (
      <div className="flex items-center gap-2 text-sm text-[var(--color-allow)]">
        <ShieldCheck className="size-4" aria-hidden /> No sensitive data detected.
      </div>
    )
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-[var(--text-muted)]">
          <tr>
            <th className="py-2 pr-3 font-medium">Detected</th>
            <th className="py-2 pr-3 font-medium">Severity</th>
            <th className="py-2 pr-3 font-medium">Confidence</th>
            <th className="py-2 pr-3 font-medium">Action</th>
            <th className="py-2 font-medium">Why</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-t align-top" style={{ borderColor: 'var(--border)' }}>
              <td className="py-2 pr-3">
                <div className="font-medium">{f.entity_type}</div>
                <div className="font-mono text-xs text-[var(--text-muted)]">{f.rule_id}</div>
              </td>
              <td className="py-2 pr-3"><SeverityText severity={f.severity} /></td>
              <td className="py-2 pr-3 tabular-nums">{Math.round(f.confidence * 100)}%</td>
              <td className="py-2 pr-3"><ActionBadge action={f.action} /></td>
              <td className="py-2 text-xs text-[var(--text-muted)]">{f.explanation}<br />{f.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function CodeFindingsList({ findings }: { findings: CodeFinding[] }) {
  if (!findings.length) return null
  return (
    <div className="rounded-lg border p-3" style={{ borderColor: 'color-mix(in srgb, var(--color-block) 35%, transparent)' }}>
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-[var(--color-block)]">
        <ShieldAlert className="size-4" aria-hidden /> Security issues in generated code
      </div>
      <ul className="space-y-1.5 text-sm">
        {findings.map((f, i) => (
          <li key={i} className="flex flex-wrap items-baseline gap-2">
            <SeverityText severity={f.severity} />
            <Badge>{f.cwe}</Badge>
            <span className="font-mono text-xs text-[var(--text-muted)]">block {f.block + 1}, line {f.line}</span>
            <span>{f.message}</span>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs text-[var(--text-muted)]">Pattern-based warnings, not a proof that the code is safe.</p>
    </div>
  )
}
