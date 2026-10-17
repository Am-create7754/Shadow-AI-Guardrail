// Extension settings, stored in chrome.storage.local. The API key lives only in
// chrome.storage.session: memory only, cleared when the browser closes, and -
// unlike storage.local - not readable by content scripts, which run inside
// third-party sites. (A "remember the key" option was removed after review for
// that reason: content scripts can read storage.local by default.)
//
// An administrator can pin settings with Chrome enterprise policy
// (chrome.storage.managed, see managed_schema.json); pinned values win.

export type FailMode = 'block' | 'allow'

export interface Settings {
  /** Gateway origin, e.g. http://127.0.0.1:8000 */
  gatewayUrl: string
  /** What to do when the gateway cannot give a decision. */
  failMode: FailMode
  enabled: boolean
}

export const DEFAULTS: Settings = {
  gatewayUrl: 'http://127.0.0.1:8000',
  failMode: 'block',
  enabled: true,
}

export type ManagedKey = 'gatewayUrl' | 'failMode' | 'enabled'

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]'])

/**
 * Validate a gateway address and reduce it to an origin. HTTPS is required,
 * except for this machine (the API key must never cross a network in clear).
 * Throws an Error with a user-facing message.
 */
export function normalizeGatewayUrl(input: string): string {
  let u: URL
  try {
    u = new URL(input.trim())
  } catch {
    throw new Error('Enter a full address, e.g. https://guardrail.example.com')
  }
  if (u.username || u.password) throw new Error('The address must not contain a user name or password')
  if (u.search || u.hash) throw new Error('The address must not contain ? or #')
  if (u.pathname !== '/' && u.pathname !== '') throw new Error('Enter only the gateway origin, without a path')
  if (u.protocol === 'https:') return u.origin
  if (u.protocol === 'http:' && LOOPBACK.has(u.hostname)) return u.origin
  throw new Error('Use https:// (plain http is allowed only for 127.0.0.1 / localhost)')
}

/** Host-permission pattern for a gateway origin. */
export function originPattern(origin: string): string {
  const u = new URL(origin)
  return `${u.protocol}//${u.hostname}/*`
}

function coerce(raw: Record<string, unknown>): Partial<Settings> {
  const out: Partial<Settings> = {}
  if (typeof raw.gatewayUrl === 'string') {
    try {
      out.gatewayUrl = normalizeGatewayUrl(raw.gatewayUrl)
    } catch {
      // An explicit but invalid address must not fall back to the default
      // (localhost): the extension then reports "not configured" and fails closed.
      out.gatewayUrl = ''
    }
  }
  if (raw.failMode === 'block' || raw.failMode === 'allow') out.failMode = raw.failMode
  if (typeof raw.enabled === 'boolean') out.enabled = raw.enabled
  return out
}

async function managedValues(): Promise<Partial<Settings>> {
  try {
    return coerce(await chrome.storage.managed.get(null))
  } catch {
    return {} // no policy installed (or not supported on this platform)
  }
}

export async function loadSettings(): Promise<{ settings: Settings; managed: ManagedKey[] }> {
  const local = coerce(await chrome.storage.local.get(null))
  const managed = await managedValues()
  return {
    settings: { ...DEFAULTS, ...local, ...managed },
    managed: Object.keys(managed) as ManagedKey[],
  }
}

export async function saveSettings(patch: Partial<Settings>): Promise<void> {
  await chrome.storage.local.set(patch)
}

/** API keys look like grk_<prefix>_<secret>. */
export function isApiKey(value: string): boolean {
  return /^grk_[A-Za-z0-9]{4,32}_[A-Za-z0-9_-]{16,128}$/.test(value)
}

/** The non-secret part, for display ("grk_ab12cd34_…"). */
export function keyPrefix(value: string): string {
  return value.split('_', 2).join('_') + '_…'
}

export async function loadApiKey(): Promise<string | null> {
  const session = await chrome.storage.session.get('apiKey')
  return typeof session.apiKey === 'string' ? session.apiKey : null
}

export async function saveApiKey(key: string | null): Promise<void> {
  // Also clears a key remembered by an earlier version in storage.local.
  await chrome.storage.local.remove('apiKey')
  if (key === null) await chrome.storage.session.remove('apiKey')
  else await chrome.storage.session.set({ apiKey: key })
}
