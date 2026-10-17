// Service worker: the only part of the extension that holds the API key and
// talks to the gateway.

import { loadApiKey, loadSettings } from './lib/config'
import { handleMessage } from './lib/router'

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender, {
    extensionId: chrome.runtime.id,
    extensionOrigin: chrome.runtime.getURL(''),
    fetch: (input, init) => fetch(input, init),
    loadSettings: async () => (await loadSettings()).settings,
    loadApiKey,
  })
    .then(sendResponse)
    .catch(() => sendResponse({ error: 'internal' }))
  return true // respond asynchronously
})
