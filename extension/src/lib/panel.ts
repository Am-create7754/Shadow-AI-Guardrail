// The warning panel shown on top of the AI site. It lives in a closed shadow
// root (the page's CSS and scripts cannot restyle or read into it) and is built
// with DOM APIs only: every gateway- or page-derived string is set as text,
// never parsed as HTML.

import type { Verdict } from './messages'
import { REASON_TEXT } from './messages'

export type Choice = 'replace' | 'dismiss' | 'send_unchecked'

interface Content {
  tone: 'warn' | 'block'
  title: string
  body: string
  findings: string[]
  preview: string | null
  buttons: { label: string; choice: Choice; primary?: boolean }[]
}

/** What is being checked: the typed prompt, or a file about to be uploaded. */
export type Subject = { kind: 'prompt' } | { kind: 'file'; name: string }

const PROMPT: Subject = { kind: 'prompt' }

export function describe(verdict: Verdict, subject: Subject = PROMPT): Content | null {
  if (verdict.kind === 'disabled') return null
  if (subject.kind === 'file') return describeFile(verdict, subject.name)
  if (verdict.kind === 'uncheckable') return null // only files can be uncheckable
  if (verdict.kind === 'unavailable') {
    return {
      tone: 'block',
      title: verdict.failMode === 'block' ? 'Prompt not sent - guardrail unavailable' : 'Prompt not checked',
      body:
        REASON_TEXT[verdict.reason] +
        (verdict.failMode === 'block'
          ? ' Your organisation requires every prompt to be checked first.'
          : ' Your organisation allows sending without a check while the gateway is unavailable.'),
      findings: [],
      preview: null,
      buttons:
        verdict.failMode === 'block'
          ? [{ label: 'OK', choice: 'dismiss', primary: true }]
          : [
              { label: 'Send without check', choice: 'send_unchecked' },
              { label: 'Cancel', choice: 'dismiss', primary: true },
            ],
    }
  }
  const findings = [...new Set(verdict.findings.map((f) => `${f.entityType} (${f.severity.toLowerCase()})`))]
  switch (verdict.action) {
    case 'ALLOW':
      return null
    case 'REDACT':
      return {
        tone: 'warn',
        title: 'Sensitive data in your prompt',
        body: 'The guardrail found data that must not be sent to an external AI service. Replace it with placeholders, check the text, then send again.',
        findings,
        preview: verdict.sanitizedText,
        buttons: [
          { label: 'Replace with redacted text', choice: 'replace', primary: true },
          { label: 'Cancel', choice: 'dismiss' },
        ],
      }
    case 'REQUIRE_APPROVAL':
      return {
        tone: 'block',
        title: 'This prompt needs approval',
        body: 'It contains material your policy only allows with administrator approval. It was not sent. Submit it through the company AI gateway, where it can be reviewed.',
        findings,
        preview: null,
        buttons: [{ label: 'Edit my prompt', choice: 'dismiss', primary: true }],
      }
    case 'BLOCK':
      return {
        tone: 'block',
        title: 'Prompt blocked',
        body: 'It contains data your policy never allows to leave the organisation. It was not sent. Remove the sensitive data and try again.',
        findings,
        preview: null,
        buttons: [{ label: 'Edit my prompt', choice: 'dismiss', primary: true }],
      }
  }
}

function describeFile(verdict: Exclude<Verdict, { kind: 'disabled' }>, name: string): Content | null {
  const file = `"${name.slice(0, 120)}"`
  const ok = { label: 'OK', choice: 'dismiss' as const, primary: true }
  if (verdict.kind === 'uncheckable') {
    const warn = verdict.uploadPolicy === 'warn'
    return {
      tone: warn ? 'warn' : 'block',
      title: warn ? 'This file cannot be checked' : 'Upload blocked - file cannot be checked',
      body: `${file} is not a text file, so the guardrail cannot see what it contains.` +
        (warn
          ? ' Upload it only if you are sure it holds no confidential data, credentials or personal data.'
          : ' Your organisation only allows uploads that can be checked. Copy the relevant text into the prompt instead.'),
      findings: [],
      preview: null,
      buttons: warn
        ? [
            { label: 'Upload anyway', choice: 'send_unchecked' },
            { label: 'Cancel', choice: 'dismiss', primary: true },
          ]
        : [ok],
    }
  }
  if (verdict.kind === 'unavailable') {
    const allow = verdict.failMode === 'allow'
    return {
      tone: 'block',
      title: allow ? 'File not checked' : 'Upload blocked - guardrail unavailable',
      body: `${file}: ${REASON_TEXT[verdict.reason]}` +
        (allow ? ' Your organisation allows uploading without a check while the gateway is unavailable.' : ' Your organisation requires every upload to be checked first.'),
      findings: [],
      preview: null,
      buttons: allow
        ? [
            { label: 'Upload without check', choice: 'send_unchecked' },
            { label: 'Cancel', choice: 'dismiss', primary: true },
          ]
        : [ok],
    }
  }
  if (verdict.action === 'ALLOW') return null
  const findings = [...new Set(verdict.findings.map((f) => `${f.entityType} (${f.severity.toLowerCase()})`))]
  // A file cannot be rewritten in place: anything but ALLOW stops the upload.
  return {
    tone: 'block',
    title: verdict.action === 'REQUIRE_APPROVAL' ? 'Upload needs approval' : 'Upload blocked - sensitive data in file',
    body: `${file} contains data that must not be sent to an external AI service. It was not uploaded. Remove the data from the file (or share only the parts that are needed) and try again.`,
    findings,
    preview: null,
    buttons: [ok],
  }
}

const STYLE = `
:host { all: initial; }
.backdrop { position: fixed; inset: 0; background: rgba(15,23,42,.45); display: flex; align-items: center; justify-content: center; z-index: 2147483647; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
.panel { box-sizing: border-box; width: min(520px, calc(100vw - 32px)); max-height: calc(100vh - 32px); overflow: auto; background: #fff; color: #0f172a; border-radius: 12px; padding: 20px; box-shadow: 0 20px 50px rgba(0,0,0,.3); border-top: 4px solid var(--tone); }
.warn { --tone: #d97706; } .block { --tone: #dc2626; }
h2 { margin: 0 0 8px; font-size: 16px; }
p { margin: 0 0 12px; }
ul { margin: 0 0 12px; padding-left: 18px; }
pre { margin: 0 0 12px; padding: 10px; background: #f1f5f9; border-radius: 8px; white-space: pre-wrap; word-break: break-word; max-height: 200px; overflow: auto; font: 12px/1.5 ui-monospace, Consolas, monospace; }
.brand { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #64748b; margin-bottom: 6px; }
.buttons { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
button { font: inherit; border-radius: 8px; padding: 8px 14px; border: 1px solid #cbd5e1; background: #fff; color: #0f172a; cursor: pointer; }
button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
button:focus-visible { outline: 3px solid #93c5fd; outline-offset: 2px; }
@media (prefers-color-scheme: dark) {
  .panel { background: #0f172a; color: #e2e8f0; } pre { background: #1e293b; }
  button { background: #1e293b; color: #e2e8f0; border-color: #334155; }
}
`

/** Show the panel and resolve with the user's choice. */
export function showPanel(
  doc: Document,
  verdict: Verdict,
  mode: ShadowRootMode = 'closed',
  subject: Subject = PROMPT,
): Promise<Choice> {
  const content = describe(verdict, subject)
  if (!content) return Promise.resolve('dismiss')
  const host = doc.createElement('div')
  host.setAttribute('data-guardrail-panel', '')
  const root = host.attachShadow({ mode }) // 'open' only in tests
  const el = (tag: string, text?: string, cls?: string): HTMLElement => {
    const e = doc.createElement(tag)
    if (text !== undefined) e.textContent = text
    if (cls) e.className = cls
    return e
  }

  const style = el('style', STYLE)
  const backdrop = el('div', undefined, 'backdrop')
  const panel = el('div', undefined, `panel ${content.tone}`)
  panel.setAttribute('role', 'alertdialog')
  panel.setAttribute('aria-modal', 'true')
  panel.setAttribute('aria-labelledby', 'gr-title')
  panel.append(el('div', 'Shadow AI Guardrail', 'brand'))
  const title = el('h2', content.title)
  title.id = 'gr-title'
  panel.append(title, el('p', content.body))
  if (content.findings.length) {
    const list = el('ul')
    for (const f of content.findings) list.append(el('li', f))
    panel.append(list)
  }
  if (content.preview !== null) panel.append(el('pre', content.preview.slice(0, 4000)))
  const buttons = el('div', undefined, 'buttons')
  panel.append(buttons)
  backdrop.append(panel)
  root.append(style, backdrop)

  return new Promise((resolve) => {
    const finish = (choice: Choice): void => {
      doc.removeEventListener('keydown', onKey, true)
      clearInterval(watch)
      host.remove()
      resolve(choice)
    }
    // A page (or its framework re-rendering) may remove the panel: treat that as
    // "dismiss", or the guard would wait forever and swallow every later send.
    const watch = setInterval(() => {
      if (!host.isConnected) finish('dismiss')
    }, 500)
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopImmediatePropagation()
        finish('dismiss')
      }
    }
    let primary: HTMLButtonElement | null = null
    for (const b of content.buttons) {
      const button = el('button', b.label, b.primary ? 'primary' : undefined) as HTMLButtonElement
      button.type = 'button'
      button.dataset.choice = b.choice
      button.addEventListener('click', () => finish(b.choice))
      buttons.append(button)
      if (b.primary) primary = button
    }
    doc.addEventListener('keydown', onKey, true)
    ;(doc.body ?? doc.documentElement).append(host)
    primary?.focus()
  })
}
