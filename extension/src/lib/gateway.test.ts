import { describe, expect, it, vi } from 'vitest'

import { DEFAULTS, type Settings } from './config'
import { MAX_TEXT, inspectPrompt, whoAmI } from './gateway'

const KEY = ['grk', 'a1b2c3d4e5f6', 'k'.repeat(43)].join('_')
const settings: Settings = { ...DEFAULTS, gatewayUrl: 'http://127.0.0.1:8000' }

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const redact = {
  action: 'REDACT',
  risk_score: 55,
  reasons: ['PASSWORD (category SECRET -> REDACT)'],
  sanitized_text: 'db_password=[PASSWORD_1]',
  findings: [
    { entity_type: 'PASSWORD', severity: 'HIGH', action: 'REDACT', start: 12, end: 26 },
    { entity_type: 'HIGH_ENTROPY_SECRET', severity: 'LOW', action: 'ALLOW' },
  ],
}

describe('inspectPrompt', () => {
  it('posts the prompt to the configured gateway only, with the key and no cookies', async () => {
    const fetch = vi.fn().mockResolvedValue(json(200, redact))
    await inspectPrompt(fetch, settings, KEY, 'db_password=hunter2hunter', 'chatgpt.com')
    expect(fetch).toHaveBeenCalledOnce()
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://127.0.0.1:8000/v1/inspect')
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${KEY}`)
    expect(init.credentials).toBe('omit')
    expect(init.redirect).toBe('error')
    expect(init.referrerPolicy).toBe('no-referrer')
    expect(init.signal).toBeInstanceOf(AbortSignal)
    expect(JSON.parse(init.body as string)).toEqual({ text: 'db_password=hunter2hunter', source: 'extension:chatgpt.com' })
  })

  it('returns the decision with public finding metadata only', async () => {
    const fetch = vi.fn().mockResolvedValue(json(200, redact))
    const v = await inspectPrompt(fetch, settings, KEY, 'x', 'claude.ai')
    expect(v).toEqual({
      kind: 'decision',
      action: 'REDACT',
      sanitizedText: 'db_password=[PASSWORD_1]',
      findings: [{ entityType: 'PASSWORD', severity: 'HIGH' }],
      reasons: ['PASSWORD (category SECRET -> REDACT)'],
      riskScore: 55,
    })
  })

  it('never passes on sanitized text for a block', async () => {
    const fetch = vi.fn().mockResolvedValue(json(200, { ...redact, action: 'BLOCK', sanitized_text: 'x' }))
    const v = await inspectPrompt(fetch, settings, KEY, 'x', 'claude.ai')
    expect(v).toMatchObject({ kind: 'decision', action: 'BLOCK', sanitizedText: null })
  })

  it.each([
    [401, 'unauthorized'],
    [403, 'unauthorized'],
    [429, 'rate_limited'],
    [422, 'too_long'],
    [500, 'unreachable'],
    [503, 'unreachable'],
    [404, 'bad_response'],
  ])('maps HTTP %i to %s', async (status, reason) => {
    const fetch = vi.fn().mockResolvedValue(json(status, { error: {} }))
    const v = await inspectPrompt(fetch, { ...settings, failMode: 'allow' }, KEY, 'x', 'claude.ai')
    expect(v).toEqual({ kind: 'unavailable', reason, failMode: reason === 'too_long' ? 'block' : 'allow' })
  })

  it('handles network failure, bad JSON and unknown actions as unavailable', async () => {
    for (const fetch of [
      vi.fn().mockRejectedValue(new TypeError('Failed to fetch')),
      vi.fn().mockResolvedValue(new Response('<html>', { status: 200 })),
      vi.fn().mockResolvedValue(json(200, { action: 'MAYBE' })),
      vi.fn().mockResolvedValue(json(200, { action: 'REDACT' })), // no sanitized text
    ]) {
      const v = await inspectPrompt(fetch, settings, KEY, 'x', 'claude.ai')
      expect(v.kind).toBe('unavailable')
    }
  })

  it('does not call the gateway without a key or address, and never lets oversized prompts through', async () => {
    const fetch = vi.fn()
    expect(await inspectPrompt(fetch, settings, null, 'x', 'claude.ai')).toMatchObject({ reason: 'not_configured', failMode: 'block' })
    expect(await inspectPrompt(fetch, { ...settings, gatewayUrl: '' }, KEY, 'x', 'claude.ai')).toMatchObject({ reason: 'not_configured' })
    expect(await whoAmI(fetch, { ...settings, gatewayUrl: '' }, KEY)).toEqual({ ok: false, reason: 'not_configured' })
    const v = await inspectPrompt(fetch, { ...settings, failMode: 'allow' }, KEY, 'a'.repeat(MAX_TEXT + 1), 'claude.ai')
    expect(v).toEqual({ kind: 'unavailable', reason: 'too_long', failMode: 'block' })
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('whoAmI', () => {
  it('reports the signed-in user or the failure reason', async () => {
    expect(await whoAmI(vi.fn().mockResolvedValue(json(200, { username: 'dev', role: 'developer' })), settings, KEY)).toEqual({
      ok: true,
      username: 'dev',
      role: 'developer',
    })
    expect(await whoAmI(vi.fn().mockResolvedValue(json(401, {})), settings, KEY)).toEqual({ ok: false, reason: 'unauthorized' })
    expect(await whoAmI(vi.fn().mockRejectedValue(new Error('x')), settings, KEY)).toEqual({ ok: false, reason: 'unreachable' })
  })
})
