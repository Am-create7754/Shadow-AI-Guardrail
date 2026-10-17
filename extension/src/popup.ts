import { loadSettings, saveSettings } from './lib/config'
import type { Status } from './lib/messages'
import { REASON_TEXT } from './lib/messages'

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T

async function render(): Promise<void> {
  const { managed } = await loadSettings()
  const status = (await chrome.runtime.sendMessage({ type: 'status' })) as Status
  $('gateway').textContent = status.gatewayUrl
  $('failmode').textContent = status.failMode === 'block' ? 'block the prompt' : 'let the user decide'
  const enabled = $<HTMLInputElement>('enabled')
  enabled.checked = status.enabled
  enabled.disabled = managed.includes('enabled')
  $('locked').hidden = !enabled.disabled
  const line = $('status')
  if (!status.enabled) {
    line.textContent = 'Off - prompts are not checked.'
    line.className = 'bad'
  } else if (status.connection.ok) {
    $('user').textContent = `${status.connection.username} (${status.connection.role})`
    line.textContent = 'Active - prompts are checked before they are sent.'
    line.className = 'good'
  } else {
    line.textContent = REASON_TEXT[status.connection.reason]
    line.className = 'bad'
  }
}

$('enabled').addEventListener('change', (e) => {
  void saveSettings({ enabled: (e.target as HTMLInputElement).checked }).then(render)
})
$('options').addEventListener('click', () => void chrome.runtime.openOptionsPage())
void render()
