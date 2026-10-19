// Read-only check of the extension's site selectors against the LIVE public
// pages. Opens each site logged out in a temporary Chrome profile with the
// extension installed and reports whether the prompt editor and the send
// button the extension relies on are present and whether its content script
// recognised them. It never types, sends, uploads, logs in or attempts to pass
// a bot check - a challenge page is reported as "not reachable".
//
//   node e2e/live_selectors.mjs        (after `npm run build`)

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer from 'puppeteer-core'

const EXT = resolve(fileURLToPath(new URL('.', import.meta.url)), '..')
const CHROME = process.env.CHROME_PATH ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
// Same selectors as src/lib/sites.ts (kept literal: this script runs without a TS build step).
const sites = [
  { id: 'chatgpt.com', url: 'https://chatgpt.com/', editor: '#prompt-textarea, div.ProseMirror[contenteditable="true"]', send: 'button[data-testid="send-button"], #composer-submit-button, button[aria-label="Send prompt"], form button[type="submit"]' },
  { id: 'claude.ai', url: 'https://claude.ai/new', editor: 'div.ProseMirror[contenteditable="true"], fieldset [contenteditable="true"]', send: 'button[aria-label="Send message"], button[aria-label="Send Message"]' },
  { id: 'gemini.google.com', url: 'https://gemini.google.com/app', editor: 'rich-textarea .ql-editor, div.ql-editor[contenteditable="true"]', send: 'button.send-button, button[aria-label="Send message"]' },
  { id: 'copilot.com', url: 'https://copilot.com/', editor: 'textarea#userInput, textarea[data-testid="composer-input"]', send: 'button[data-testid="submit-button"], button[aria-label="Submit message"]' },
  { id: 'copilot.microsoft.com', url: 'https://copilot.microsoft.com/', editor: 'textarea#userInput, textarea[data-testid="composer-input"]', send: 'button[data-testid="submit-button"], button[aria-label="Submit message"]' },
]

const profile = mkdtempSync(join(tmpdir(), 'guardrail-live-'))
const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, pipe: true, enableExtensions: true, userDataDir: profile })
try {
  await browser.installExtension(join(EXT, 'dist'))
  for (const s of sites) {
    const page = await browser.newPage()
    let note = ''
    try {
      const res = await page.goto(s.url, { waitUntil: 'domcontentloaded', timeout: 30000 })
      await new Promise((r) => setTimeout(r, 6000)) // let the app render
      const info = await page.evaluate((sel) => {
        const ed = document.querySelector(sel.editor)
        return {
          finalUrl: location.href,
          title: document.title,
          editor: !!ed,
          editorKind: ed ? (ed.tagName === 'TEXTAREA' ? 'textarea' : ed.isContentEditable ? 'contenteditable' : ed.tagName) : null,
          send: !!document.querySelector(sel.send),
          anyTextarea: document.querySelectorAll('textarea').length,
          anyEditable: document.querySelectorAll('[contenteditable="true"]').length,
        }
      }, s)
      note = `HTTP ${res?.status()} ${JSON.stringify(info)}`
    } catch (e) {
      note = `not reachable: ${String(e.message).slice(0, 120)}`
    }
    console.log(`${s.id}: ${note}`)
    await page.close()
  }
} finally {
  await browser.close()
  rmSync(profile, { recursive: true, force: true, maxRetries: 5 })
}
