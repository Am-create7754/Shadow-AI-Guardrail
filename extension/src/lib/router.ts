// Service-worker message handling, separated from chrome.* wiring for testing.
//
// Trust rules: messages must come from this extension. "inspect" is accepted
// only from a content script in a tab of a supported https site (the site id is
// derived from the sender's URL, not from the message). "status" is accepted
// only from the extension's own pages (popup, options).

import { keyPrefix, type Settings } from './config'
import { inspectPrompt, whoAmI } from './gateway'
import type { Message, Status, Verdict } from './messages'
import { siteForUrl } from './sites'

export interface RouterDeps {
  extensionId: string
  extensionOrigin: string // chrome-extension://<id>/
  fetch: typeof fetch
  loadSettings: () => Promise<Settings>
  loadApiKey: () => Promise<string | null>
}

export interface Sender {
  id?: string
  url?: string
  tab?: { id?: number }
}

export async function handleMessage(msg: unknown, sender: Sender, deps: RouterDeps): Promise<Verdict | Status | { error: string }> {
  if (sender.id !== deps.extensionId) return { error: 'forbidden' }
  if (typeof msg !== 'object' || msg === null) return { error: 'bad_message' }
  const m = msg as Message

  if (m.type === 'inspect') {
    const site = sender.tab ? siteForUrl(sender.url) : null
    if (!site || typeof m.text !== 'string') return { error: 'forbidden' }
    const settings = await deps.loadSettings()
    if (!settings.enabled) return { kind: 'disabled' }
    return inspectPrompt(deps.fetch, settings, await deps.loadApiKey(), m.text, site.id)
  }

  if (m.type === 'status') {
    if (!isExtensionPage(sender.url, deps.extensionOrigin)) return { error: 'forbidden' }
    const settings = await deps.loadSettings()
    const key = await deps.loadApiKey()
    return {
      enabled: settings.enabled,
      configured: key !== null,
      gatewayUrl: settings.gatewayUrl,
      failMode: settings.failMode,
      connection: key ? await whoAmI(deps.fetch, settings, key) : { ok: false, reason: 'not_configured' },
      keyPrefix: key ? keyPrefix(key) : null,
    }
  }
  return { error: 'bad_message' }
}

/** The popup and options page (which may be open in a tab). Content scripts
 *  always report the web page's URL, never an extension origin. */
function isExtensionPage(url: string | undefined, extensionOrigin: string): boolean {
  if (!url) return false
  try {
    // Not URL.origin: for non-special schemes such as chrome-extension: it can be
    // the opaque string "null", which would make every extension look the same.
    const a = new URL(url)
    const b = new URL(extensionOrigin)
    return a.protocol === b.protocol && a.host !== '' && a.host === b.host
  } catch {
    return false
  }
}
