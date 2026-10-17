import { describe, expect, it, vi } from 'vitest'

import { DEFAULTS } from './config'
import { handleMessage, type RouterDeps } from './router'

const KEY = ['grk', 'a1b2c3d4e5f6', 's'.repeat(43)].join('_')
const ID = 'abcdefghijklmnopabcdefghijklmnop'
const ORIGIN = `chrome-extension://${ID}/`

function deps(overrides: Partial<RouterDeps> = {}): RouterDeps {
  return {
    extensionId: ID,
    extensionOrigin: ORIGIN,
    fetch: vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ action: 'ALLOW', sanitized_text: 'hi', findings: [], username: 'dev', role: 'developer' }), {
        status: 200,
      }),
    ),
    loadSettings: async () => DEFAULTS,
    loadApiKey: async () => KEY,
    ...overrides,
  }
}

const tabSender = (url: string) => ({ id: ID, url, tab: { id: 1 } })

describe('inspect messages', () => {
  it('are answered for content scripts on supported https sites', async () => {
    const d = deps()
    const v = await handleMessage({ type: 'inspect', text: 'hi' }, tabSender('https://chatgpt.com/c/123'), d)
    expect(v).toMatchObject({ kind: 'decision', action: 'ALLOW' })
    const init = vi.mocked(d.fetch).mock.calls[0]![1] as RequestInit
    const body = JSON.parse(init.body as string)
    expect(body.source).toBe('extension:chatgpt.com') // from the sender URL, not the message
  })

  it.each([
    ['another extension', { id: 'other', url: 'https://chatgpt.com/', tab: { id: 1 } }],
    ['an unsupported site', tabSender('https://evil.example/')],
    ['a look-alike host', tabSender('https://chatgpt.com.evil.example/')],
    ['plain http', tabSender('http://chatgpt.com/')],
    ['a non-tab context', { id: ID, url: 'https://chatgpt.com/' }],
  ])('are refused from %s', async (_name, sender) => {
    const d = deps()
    expect(await handleMessage({ type: 'inspect', text: 'hi' }, sender, d)).toEqual({ error: 'forbidden' })
    expect(d.fetch).not.toHaveBeenCalled()
  })

  it('report "disabled" without contacting the gateway when switched off', async () => {
    const d = deps({ loadSettings: async () => ({ ...DEFAULTS, enabled: false }) })
    expect(await handleMessage({ type: 'inspect', text: 'hi' }, tabSender('https://claude.ai/'), d)).toEqual({ kind: 'disabled' })
    expect(d.fetch).not.toHaveBeenCalled()
  })

  it('reject malformed messages', async () => {
    for (const msg of [null, 'inspect', { type: 'inspect', text: 42 }, { type: 'steal-key' }]) {
      const res = await handleMessage(msg, tabSender('https://claude.ai/'), deps())
      expect(res).toHaveProperty('error')
    }
  })
})

describe('status messages', () => {
  it('are answered only for the extension pages and never contain the key', async () => {
    const res = await handleMessage({ type: 'status' }, { id: ID, url: `${ORIGIN}popup.html` }, deps())
    expect(res).toMatchObject({ enabled: true, configured: true, connection: { ok: true, username: 'dev' } })
    expect(JSON.stringify(res)).not.toContain('s'.repeat(20))
    expect(await handleMessage({ type: 'status' }, tabSender('https://chatgpt.com/'), deps())).toEqual({ error: 'forbidden' })
  })

  it('are answered for the options page opened in a tab', async () => {
    // Regression (Phase 6 review): options_ui open_in_tab sets sender.tab.
    const res = await handleMessage({ type: 'status' }, { id: ID, url: `${ORIGIN}options.html`, tab: { id: 7 } }, deps())
    expect(res).toMatchObject({ configured: true })
    const other = await handleMessage({ type: 'status' }, { id: ID, url: 'chrome-extension://another/options.html' }, deps())
    expect(other).toEqual({ error: 'forbidden' })
  })
})
