import { afterEach, describe, expect, it, vi } from 'vitest'

import type { Verdict } from './messages'
import { describe as describeVerdict, showPanel } from './panel'

afterEach(() => {
  document.body.innerHTML = ''
})

const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>'
const redact: Verdict = {
  kind: 'decision',
  action: 'REDACT',
  sanitizedText: `${hostile} [PASSWORD_1]`,
  findings: [{ entityType: '<b>PASSWORD</b>', severity: 'HIGH' }],
  reasons: [],
  riskScore: 55,
}

const root = () => document.querySelector('[data-guardrail-panel]')?.shadowRoot ?? null

describe('showPanel', () => {
  it('renders gateway text as inert text and resolves with the chosen button', async () => {
    const choice = showPanel(document, redact, 'open')
    const r = root()!
    expect(r.querySelector('img, script, b')).toBeNull()
    expect(r.querySelector('pre')?.textContent).toBe(`${hostile} [PASSWORD_1]`)
    expect(r.querySelector('li')?.textContent).toBe('<b>PASSWORD</b> (high)')
    expect(r.querySelector('[role=alertdialog]')).not.toBeNull()
    r.querySelector<HTMLButtonElement>('button[data-choice=replace]')!.click()
    expect(await choice).toBe('replace')
    expect(document.querySelector('[data-guardrail-panel]')).toBeNull()
  })

  it('closes on Escape as "dismiss"', async () => {
    const choice = showPanel(document, redact, 'open')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(await choice).toBe('dismiss')
  })

  it('resolves "dismiss" if the page removes the panel, so the guard is not stuck (Low)', async () => {
    vi.useFakeTimers()
    try {
      const choice = showPanel(document, redact, 'open')
      document.querySelector('[data-guardrail-panel]')!.remove()
      vi.advanceTimersByTime(600)
      expect(await choice).toBe('dismiss')
    } finally {
      vi.useRealTimers()
    }
  })

  it('uses a closed shadow root by default, so the site cannot read it', () => {
    void showPanel(document, redact)
    const host = document.querySelector('[data-guardrail-panel]')!
    expect(host.shadowRoot).toBeNull()
  })
})

describe('panel content', () => {
  it('offers sending unchecked only when policy allows it', () => {
    const block = describeVerdict({ kind: 'unavailable', reason: 'unreachable', failMode: 'block' })!
    expect(block.buttons.map((b) => b.choice)).toEqual(['dismiss'])
    const allow = describeVerdict({ kind: 'unavailable', reason: 'unreachable', failMode: 'allow' })!
    expect(allow.buttons.map((b) => b.choice)).toContain('send_unchecked')
  })

  it('never offers to send a blocked or held prompt', () => {
    for (const action of ['BLOCK', 'REQUIRE_APPROVAL'] as const) {
      const c = describeVerdict({ ...redact, action, sanitizedText: null } as Verdict)!
      expect(c.buttons.map((b) => b.choice)).toEqual(['dismiss'])
      expect(c.preview).toBeNull()
    }
  })
})
