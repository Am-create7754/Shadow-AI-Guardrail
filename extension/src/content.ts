// Content script for supported AI sites (see lib/sites.ts and manifest.json).
// Holds no secrets: it asks the service worker for a verdict on the prompt.

import { installGuard } from './lib/guard'
import type { Verdict } from './lib/messages'
import { showPanel } from './lib/panel'
import { siteForHost } from './lib/sites'

const site = siteForHost(location.hostname)
if (site) {
  installGuard({
    win: window,
    site,
    inspect: async (text) => {
      const res = (await chrome.runtime.sendMessage({ type: 'inspect', text })) as Verdict | { error: string } | undefined
      if (!res || 'error' in res) throw new Error('no verdict')
      return res
    },
    showPanel: (doc, verdict) => showPanel(doc, verdict),
  })
}
