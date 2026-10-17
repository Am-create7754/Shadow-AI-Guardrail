// Content script for supported AI sites (see lib/sites.ts and manifest.json).
// Holds no secrets: it asks the service worker for a verdict on the prompt.

import { installGuard } from './lib/guard'
import type { Verdict } from './lib/messages'
import { showPanel } from './lib/panel'
import { siteForHost } from './lib/sites'
import { installUploadGuard } from './lib/uploads'

async function ask(message: object): Promise<Verdict> {
  const res = (await chrome.runtime.sendMessage(message)) as Verdict | { error: string } | undefined
  if (!res || 'error' in res) throw new Error('no verdict')
  return res
}

const site = siteForHost(location.hostname)
if (site) {
  installGuard({
    win: window,
    site,
    inspect: (text) => ask({ type: 'inspect', text }),
    showPanel: (doc, verdict) => showPanel(doc, verdict),
  })
  installUploadGuard({
    win: window,
    inspectFile: (name, text) => ask({ type: 'inspectFile', name, text }),
    showPanel: (doc, verdict, subject) => showPanel(doc, verdict, 'closed', subject),
  })
}
