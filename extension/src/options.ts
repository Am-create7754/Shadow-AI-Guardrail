import {
  isApiKey,
  keyPrefix,
  loadApiKey,
  loadSettings,
  normalizeGatewayUrl,
  originPattern,
  saveApiKey,
  saveSettings,
  type FailMode,
} from './lib/config'
import type { Status } from './lib/messages'
import { REASON_TEXT } from './lib/messages'

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T
const gateway = $<HTMLInputElement>('gateway')
const key = $<HTMLInputElement>('key')
const result = $('result')

function say(text: string, ok: boolean): void {
  result.textContent = text
  result.className = ok ? 'good' : 'bad'
}

async function load(): Promise<void> {
  const { settings, managed } = await loadSettings()
  gateway.value = settings.gatewayUrl
  gateway.disabled = managed.includes('gatewayUrl')
  for (const r of document.querySelectorAll<HTMLInputElement>('input[name=failmode]')) {
    r.checked = r.value === settings.failMode
    r.disabled = managed.includes('failMode')
  }
  $('locked').hidden = managed.length === 0
  const stored = await loadApiKey()
  // The saved key is never shown again, only its non-secret prefix.
  $('key-state').textContent = stored ? `Saved key: ${keyPrefix(stored)}` : 'No key saved. Create one in the dashboard under "API keys".'
}

async function save(e: SubmitEvent): Promise<void> {
  e.preventDefault()
  let origin: string
  try {
    origin = normalizeGatewayUrl(gateway.value)
  } catch (err) {
    say((err as Error).message, false)
    return
  }
  const typed = key.value.trim()
  if (typed && !isApiKey(typed)) {
    say('That does not look like a gateway API key (grk_…).', false)
    return
  }
  // Least privilege: ask for access to exactly this gateway origin, if the
  // manifest does not already cover it (127.0.0.1 / localhost).
  const pattern = originPattern(origin)
  if (!(await chrome.permissions.contains({ origins: [pattern] }))) {
    const granted = await chrome.permissions.request({ origins: [pattern] })
    if (!granted) {
      say('Permission to contact the gateway was not granted.', false)
      return
    }
  }
  const failMode = document.querySelector<HTMLInputElement>('input[name=failmode]:checked')?.value as FailMode | undefined
  const { managed } = await loadSettings()
  await saveSettings({
    ...(managed.includes('gatewayUrl') ? {} : { gatewayUrl: origin }),
    ...(managed.includes('failMode') || !failMode ? {} : { failMode }),
  })
  const current = typed || (await loadApiKey())
  await saveApiKey(current)
  key.value = ''
  await load()

  const status = (await chrome.runtime.sendMessage({ type: 'status' })) as Status | { error: string }
  if ('error' in status) say('The extension could not check the connection.', false)
  else if (status.connection.ok) say(`Connected as ${status.connection.username}.`, true)
  else say(REASON_TEXT[status.connection.reason], false)
}

$('form').addEventListener('submit', (e) => void save(e as SubmitEvent))
$('forget').addEventListener('click', () => {
  void saveApiKey(null).then(load).then(() => say('Key removed from this browser.', true))
})
void load()
