import { describe, expect, it } from 'vitest'

import { installChrome } from '../test/chrome'
import { DEFAULTS, isApiKey, keyPrefix, loadApiKey, loadSettings, normalizeGatewayUrl, originPattern, saveApiKey } from './config'

const KEY = ['grk', 'a1b2c3d4e5f6', 'x'.repeat(43)].join('_')

describe('normalizeGatewayUrl', () => {
  it.each([
    ['https://guardrail.example.com', 'https://guardrail.example.com'],
    ['https://guardrail.example.com/', 'https://guardrail.example.com'],
    ['  https://g.example.com:8443  ', 'https://g.example.com:8443'],
    ['http://127.0.0.1:8000', 'http://127.0.0.1:8000'],
    ['http://localhost:8000/', 'http://localhost:8000'],
    ['http://[::1]:8000', 'http://[::1]:8000'],
  ])('accepts %s', (input, origin) => {
    expect(normalizeGatewayUrl(input)).toBe(origin)
  })

  it.each([
    'http://guardrail.example.com', // key would travel in clear text
    'http://192.168.1.10:8000',
    'http://127.0.0.1.evil.example',
    'https://user:pw@guardrail.example.com',
    'https://guardrail.example.com/api',
    'https://guardrail.example.com/?x=1',
    'https://guardrail.example.com/#x',
    'javascript:alert(1)',
    'file:///C:/x',
    'not a url',
  ])('rejects %s', (input) => {
    expect(() => normalizeGatewayUrl(input)).toThrow()
  })

  it('builds a port-independent permission pattern', () => {
    expect(originPattern('https://g.example.com:8443')).toBe('https://g.example.com/*')
  })
})

describe('API keys', () => {
  it('recognises gateway keys and shows only the prefix', () => {
    expect(isApiKey(KEY)).toBe(true)
    expect(isApiKey('sk-something')).toBe(false)
    expect(isApiKey(KEY + ' ')).toBe(false)
    expect(keyPrefix(KEY)).toBe('grk_a1b2c3d4e5f6_…')
    expect(keyPrefix(KEY)).not.toContain('xxxx')
  })

  it('keeps the key in session storage only, and clears an old persisted key', async () => {
    // Regression (Phase 6 review): storage.local is readable by content scripts.
    const storage = installChrome({ local: { apiKey: KEY } })
    await saveApiKey(KEY)
    expect(storage.session.data.apiKey).toBe(KEY)
    expect(storage.local.data.apiKey).toBeUndefined()
    expect(await loadApiKey()).toBe(KEY)
    await saveApiKey(null)
    expect(await loadApiKey()).toBeNull()
  })
})

describe('loadSettings', () => {
  it('uses defaults, then stored values, with policy values winning', async () => {
    installChrome({
      local: { gatewayUrl: 'https://mine.example.com', failMode: 'allow', enabled: false },
      managed: { gatewayUrl: 'https://corp.example.com', failMode: 'block' },
    })
    const { settings, managed } = await loadSettings()
    expect(settings).toEqual({ ...DEFAULTS, gatewayUrl: 'https://corp.example.com', failMode: 'block', enabled: false })
    expect(new Set(managed)).toEqual(new Set(['failMode', 'gatewayUrl']))
  })

  it('ignores invalid values and missing policy support', async () => {
    installChrome({ local: { failMode: 'sometimes', enabled: 'yes' }, managed: 'none' })
    const { settings, managed } = await loadSettings()
    expect(settings).toEqual(DEFAULTS)
    expect(managed).toEqual([])
  })

  it('treats an explicitly set but invalid gateway as not configured, not as localhost', async () => {
    // Regression (Phase 6 review): it used to fall back to http://127.0.0.1:8000.
    installChrome({ managed: { gatewayUrl: 'http://evil.example.com' } })
    expect((await loadSettings()).settings.gatewayUrl).toBe('')
  })
})
