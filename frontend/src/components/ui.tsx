// Small, dependency-free UI primitives styled with Tailwind and the CSS tokens
// in index.css. Nothing here renders raw HTML: all content is React text.

import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'

import { ApiError } from '../api/client'
import type { Action, Severity } from '../api/types'
import { ACTION_LABEL, cx } from '../lib/format'

export function Card({ title, actions, children, className }: {
  title?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section
      className={cx('rounded-xl border bg-[var(--surface)] shadow-sm', className)}
      style={{ borderColor: 'var(--border)' }}
    >
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b px-5 py-3" style={{ borderColor: 'var(--border)' }}>
          <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'success'

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-[var(--color-brand)] text-white hover:brightness-110',
  secondary: 'border bg-[var(--surface)] hover:bg-[var(--surface-sunken)]',
  danger: 'bg-[var(--color-block)] text-white hover:brightness-110',
  success: 'bg-[var(--color-allow)] text-white hover:brightness-110',
  ghost: 'hover:bg-[var(--surface-sunken)]',
}

export function Button({ variant = 'primary', loading, children, className, disabled, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant
  loading?: boolean
}) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={cx(
        'inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition',
        'disabled:cursor-not-allowed disabled:opacity-50',
        VARIANTS[variant],
        className,
      )}
      style={variant === 'secondary' ? { borderColor: 'var(--border)' } : undefined}
    >
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  )
}

const FIELD = 'w-full rounded-lg border bg-[var(--surface)] px-3 py-2 text-sm placeholder:text-[var(--text-muted)]'

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx(FIELD, props.className)} style={{ borderColor: 'var(--border)' }} />
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx(FIELD, 'font-mono', props.className)} style={{ borderColor: 'var(--border)' }} />
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx(FIELD, props.className)} style={{ borderColor: 'var(--border)' }} />
}

export function Label({ htmlFor, children }: { htmlFor: string; children: ReactNode }) {
  return (
    <label htmlFor={htmlFor} className="mb-1 block text-xs font-medium text-[var(--text-muted)]">
      {children}
    </label>
  )
}

const ACTION_STYLE: Record<string, string> = {
  ALLOW: 'bg-[color-mix(in_srgb,var(--color-allow)_15%,transparent)] text-[var(--color-allow)]',
  REDACT: 'bg-[color-mix(in_srgb,var(--color-redact)_15%,transparent)] text-[var(--color-redact)]',
  REQUIRE_APPROVAL: 'bg-[color-mix(in_srgb,var(--color-approval)_15%,transparent)] text-[var(--color-approval)]',
  BLOCK: 'bg-[color-mix(in_srgb,var(--color-block)_15%,transparent)] text-[var(--color-block)]',
  APPROVED: 'bg-[color-mix(in_srgb,var(--color-approval)_15%,transparent)] text-[var(--color-approval)]',
}

export function ActionBadge({ action }: { action: Action | 'APPROVED' | string }) {
  return (
    <span className={cx('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold', ACTION_STYLE[action] ?? 'bg-[var(--surface-sunken)]')}>
      {ACTION_LABEL[action] ?? action}
    </span>
  )
}

const SEVERITY_STYLE: Record<Severity, string> = {
  LOW: 'text-[var(--text-muted)]',
  MEDIUM: 'text-[var(--color-redact)]',
  HIGH: 'text-[var(--color-block)]',
  CRITICAL: 'text-[var(--color-block)] font-bold',
}

export function SeverityText({ severity }: { severity: Severity }) {
  return <span className={cx('text-xs font-semibold', SEVERITY_STYLE[severity])}>{severity}</span>
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'good' | 'bad' | 'warn' }) {
  const tones = {
    neutral: 'bg-[var(--surface-sunken)] text-[var(--text-muted)]',
    good: ACTION_STYLE.ALLOW,
    bad: ACTION_STYLE.BLOCK,
    warn: ACTION_STYLE.REDACT,
  }
  return <span className={cx('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium', tones[tone])}>{children}</span>
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-[var(--text-muted)]" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden /> {label}…
    </div>
  )
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null
  const message = error instanceof Error ? error.message : 'Something went wrong'
  const requestId = error instanceof ApiError ? error.requestId : undefined
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border px-3 py-2 text-sm"
      style={{ borderColor: 'color-mix(in srgb, var(--color-block) 40%, transparent)', background: 'color-mix(in srgb, var(--color-block) 8%, transparent)' }}>
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-[var(--color-block)]" aria-hidden />
      <div>
        <div>{message}</div>
        {requestId && <div className="mt-0.5 font-mono text-xs text-[var(--text-muted)]">request {requestId}</div>}
      </div>
    </div>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-[var(--text-muted)]">{children}</div>
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="rounded-xl border bg-[var(--surface)] p-4 shadow-sm" style={{ borderColor: 'var(--border)' }}>
      <div className="text-xs font-medium text-[var(--text-muted)]">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums" style={tone ? { color: tone } : undefined}>{value}</div>
      {hint && <div className="mt-1 text-xs text-[var(--text-muted)]">{hint}</div>}
    </div>
  )
}

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-[var(--text-muted)]">{description}</p>}
      </div>
      {actions}
    </div>
  )
}
