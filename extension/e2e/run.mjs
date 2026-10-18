// End-to-end test of the PACKAGED extension in real Chrome.
//
//   node e2e/run.mjs            (after `npm run build`)
//
// * starts an isolated gateway (backend/loadtest/server.py: mock provider,
//   throwaway keys, backend/.env ignored)
// * serves local HTTPS copies of chatgpt.com and claude.ai whose composer markup
//   imitates the real sites (incl. ChatGPT's hidden fallback <textarea>), with a
//   throwaway self-signed certificate
// * launches Chrome with a temporary profile, maps those host names to the
//   local server, installs extension/dist, configures it through its real
//   options page, and acts with Chrome's own (trusted) input events
// * checks what the "site" received and what the gateway audited
//
// Environment: CHROME_PATH (default: the usual Windows install path),
// GUARDRAIL_PYTHON (default: backend/.venv's python).

import { spawn, spawnSync } from 'node:child_process'
import { createServer } from 'node:https'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer from 'puppeteer-core'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const EXT = resolve(HERE, '..')
const BACKEND = resolve(EXT, '..', 'backend')
const PY =
  process.env.GUARDRAIL_PYTHON ??
  join(BACKEND, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const CHROME =
  process.env.CHROME_PATH ??
  (process.platform === 'win32' ? 'C:/Program Files/Google/Chrome/Application/chrome.exe' : '/usr/bin/google-chrome')
const GATEWAY_PORT = 8771
const SITE_PORT = 8443
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
// Built at runtime: the repository never contains credential-shaped literals.
const SECRET = 'db_' + 'password=' + 'Hunter2x9Lq'
const CARD = '4' + '1'.repeat(15)

const results = []
function check(name, ok, detail = '') {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`)
  if (!ok && process.env.GITHUB_ACTIONS) {
    console.log(`::error title=E2E ${name.replace(/[:,]/g, ' ')}::${detail.replace(/[\r\n%]/g, ' ').slice(0, 300)}`)
  }
}

// ---- local copies of the AI sites ---------------------------------------------
const PAGES = {
  'chatgpt.com': `<!doctype html><title>ChatGPT (local copy)</title>
<form id="composer">
  <textarea class="fallback" style="display:none"></textarea>
  <div id="prompt-textarea" contenteditable="true" class="ProseMirror" style="min-height:3em;border:1px solid #999"><p></p></div>
  <button type="submit" data-testid="send-button" id="send">Send</button>
</form>
<input type="file" id="upload">
<script>
  const form = document.getElementById('composer'), ed = document.getElementById('prompt-textarea')
  const send = (body) => fetch('/__send', { method: 'POST', body: JSON.stringify({ site: 'chatgpt', ...body }) })
  form.addEventListener('submit', (e) => { e.preventDefault(); send({ text: ed.innerText.trim() }); ed.innerHTML = '<p></p>' })
  ed.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); form.requestSubmit() } })
  document.getElementById('upload').addEventListener('change', (e) => send({ upload: [...e.target.files].map((f) => f.name) }))
</script>`,
  'claude.ai': `<!doctype html><title>Claude (local copy)</title>
<fieldset>
  <div class="ProseMirror" contenteditable="true" style="min-height:3em;border:1px solid #999"><p></p></div>
  <button aria-label="Send message" id="send">Send</button>
</fieldset>
<script>
  const ed = document.querySelector('.ProseMirror')
  const send = (body) => fetch('/__send', { method: 'POST', body: JSON.stringify({ site: 'claude', ...body }) })
  document.getElementById('send').addEventListener('click', () => { send({ text: ed.innerText.trim() }); ed.innerHTML = '<p></p>' })
  ed.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); document.getElementById('send').click() } })
</script>`,
}

function startSites(certDir) {
  const received = []
  const server = createServer(
    { key: readFileSync(join(certDir, 'e2e-key.pem')), cert: readFileSync(join(certDir, 'e2e-cert.pem')) },
    (req, res) => {
      const host = (req.headers.host ?? '').split(':')[0]
      if (req.method === 'POST' && req.url === '/__send') {
        let body = ''
        req.on('data', (c) => (body += c))
        req.on('end', () => {
          received.push(JSON.parse(body))
          res.end('ok')
        })
        return
      }
      const page = PAGES[host]
      res.writeHead(page ? 200 : 404, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(page ?? 'not found')
    },
  )
  return new Promise((ok) => server.listen(SITE_PORT, '127.0.0.1', () => ok({ server, received })))
}

// ---- isolated gateway -------------------------------------------------------------
function startGateway(dir) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GUARDRAIL_')))
  const proc = spawn(PY, ['-m', 'loadtest.server', '--dir', dir, '--port', String(GATEWAY_PORT)], {
    cwd: BACKEND,
    env,
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  return new Promise((ok, fail) => {
    let out = ''
    proc.stdout.on('data', (d) => {
      out += d
      const key = /KEY (\S+)\r?\n/.exec(out)
      const admin = /ADMIN_KEY (\S+)\r?\n/.exec(out)
      if (key && admin) ok({ proc, key: key[1], admin: admin[1] })
    })
    proc.on('exit', (code) => fail(new Error(`gateway exited (${code})`)))
  })
}

async function waitFor(fn, ms = 8000) {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn()
    if (v || Date.now() > end) return v
    await sleep(100)
  }
}

async function gatewayGet(path, key) {
  const r = await fetch(`http://127.0.0.1:${GATEWAY_PORT}${path}`, { headers: { Authorization: `Bearer ${key}` } })
  return r.json()
}

// ---- the test ---------------------------------------------------------------------
async function main() {
  const work = mkdtempSync(join(tmpdir(), 'guardrail-e2e-'))
  spawnSync(PY, [join(HERE, 'make_cert.py'), work], { stdio: 'inherit' })
  const { server, received } = await startSites(work)
  const gw = await startGateway(join(work, 'gateway'))
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${GATEWAY_PORT}/health`)).ok) break
    } catch {
      await sleep(200)
    }
  }

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: process.env.E2E_HEADFUL ? false : true,
    pipe: true,
    enableExtensions: true,
    userDataDir: join(work, 'profile'),
    args: [
      `--host-resolver-rules=MAP chatgpt.com 127.0.0.1:${SITE_PORT},MAP claude.ai 127.0.0.1:${SITE_PORT}`,
      '--ignore-certificate-errors',
      '--no-first-run',
      '--no-default-browser-check',
    ],
  })
  try {
    const id = await browser.installExtension(join(EXT, 'dist'))
    check('extension installed in Chrome', /^[a-p]{32}$/.test(id), id)

    // Configure through the real options page.
    const opts = await browser.newPage()
    await opts.goto(`chrome-extension://${id}/options.html`)
    await opts.waitForFunction(() => /key/i.test(document.getElementById('key-state')?.textContent ?? ''))
    await opts.click('#gateway', { count: 3 }) // select the default address
    await opts.type('#gateway', `http://127.0.0.1:${GATEWAY_PORT}`)
    await opts.type('#key', gw.key)
    await opts.click('button[type=submit]')
    const status = await waitFor(() => opts.$eval('#result', (el) => el.textContent ?? ''))
    check('options page: save and test connection', /Connected as loadtest/.test(status), status)
    if (!/Connected/.test(status)) {
      // Diagnose from inside the extension's service worker.
      const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().includes(id))
      const worker = await sw.worker()
      console.log('debug:', await worker.evaluate(async (port) => {
        const stored = await chrome.storage.local.get(null)
        const session = await chrome.storage.session.get(null)
        let probe
        try {
          probe = (await fetch(`http://127.0.0.1:${port}/health`)).status
        } catch (e) {
          probe = `${e.name}: ${e.message}`
        }
        return JSON.stringify({ stored, hasKey: typeof session.apiKey === 'string', probe })
      }, GATEWAY_PORT))
    }
    const keyState = await opts.$eval('#key-state', (el) => el.textContent ?? '')
    check('options page shows only the key prefix', keyState.includes('grk_') && !keyState.includes(gw.key.split('_')[2]))
    await opts.close()

    // --- ChatGPT copy: secret prompt with Enter -> REDACT panel -> replace -> send
    const page = await browser.newPage()
    await page.goto('https://chatgpt.com/')
    await page.click('#prompt-textarea')
    await page.keyboard.type(`Fix this config: ${SECRET}`)
    await page.keyboard.press('Enter')
    const panel = await waitFor(() => page.$('[data-guardrail-panel]'))
    check('chatgpt: secret prompt held, warning panel shown', !!panel && received.length === 0)
    await page.keyboard.press('Enter') // focused primary button: "Replace with redacted text"
    const replaced = await waitFor(async () => {
      const t = await page.$eval('#prompt-textarea', (el) => el.innerText)
      return t.includes('[PASSWORD_1]') ? t : null
    })
    check('chatgpt: editor now holds the placeholder', !!replaced && !replaced.includes('Hunter2'), replaced ?? '')
    await page.keyboard.press('Enter') // focus is back in the editor: send the redacted text
    await waitFor(() => received.length > 0)
    check(
      'chatgpt: only the redacted prompt reached the site',
      received.length === 1 && received[0].text.includes('[PASSWORD_1]') && !received[0].text.includes('Hunter2'),
      JSON.stringify(received[0] ?? {}),
    )

    // --- send-button click with a card number: blocked (hidden textarea must not hide it)
    await page.click('#prompt-textarea')
    await page.keyboard.type(`Why was card ${CARD} declined?`)
    await page.click('#send')
    await waitFor(() => page.$('[data-guardrail-panel]'))
    await sleep(500)
    check('chatgpt: send-button click with a card number blocked', received.length === 1)
    await page.keyboard.press('Escape')

    // --- uploads through the real file chooser path (CDP DOM.setFileInputFiles)
    const envFile = join(work, 'prod.env')
    const notes = join(work, 'notes.txt')
    writeFileSync(envFile, `DB_HOST=db.internal\n${SECRET}\n`)
    writeFileSync(notes, 'meeting notes: ship on friday\n')
    const input = await page.$('#upload')
    await input.uploadFile(envFile)
    await waitFor(() => page.$('[data-guardrail-panel]'))
    await sleep(500)
    check('chatgpt: .env file with a password not uploaded', !received.some((r) => r.upload))
    await page.keyboard.press('Escape')
    await input.uploadFile(notes)
    const uploaded = await waitFor(() => received.find((r) => r.upload))
    check('chatgpt: harmless file uploaded unchanged', JSON.stringify(uploaded?.upload) === '["notes.txt"]')

    // --- a page script tries to send by itself: stopped, gateway never asked
    const before = (await gatewayGet('/v1/admin/metrics?hours=1', gw.admin)).inspections
    await sleep(1500) // outside the gesture window of the last real input
    await page.evaluate((secret) => {
      const ed = document.getElementById('prompt-textarea')
      ed.innerText = `planted by the page: ${secret}`
      ed.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }))
      document.getElementById('send').click()
      document.getElementById('composer').requestSubmit()
    }, SECRET)
    await sleep(1500)
    const after = (await gatewayGet('/v1/admin/metrics?hours=1', gw.admin)).inspections
    const sends = received.filter((r) => r.text).length
    check('page-script sends stopped without a gateway call', sends === 1 && after === before, `inspections ${before} -> ${after}`)
    await page.close()

    // --- Claude copy: harmless prompt goes straight through
    const claude = await browser.newPage()
    await claude.goto('https://claude.ai/')
    await claude.click('.ProseMirror')
    await claude.keyboard.type('How do I sort a list in Python?')
    await claude.click('#send')
    const harmless = await waitFor(() => received.find((r) => r.site === 'claude'))
    check('claude: harmless prompt sent once, unchanged', harmless?.text === 'How do I sort a list in Python?')

    // --- the gateway recorded the checks per site (metadata only)
    const m = await gatewayGet('/v1/admin/metrics?hours=1', gw.admin)
    const sources = Object.fromEntries(m.inspection_sources)
    check('gateway audited checks per site', sources['extension:chatgpt.com'] >= 4 && sources['extension:claude.ai'] >= 1, JSON.stringify(sources))
    const events = JSON.stringify(await gatewayGet('/v1/admin/audit/events?limit=200', gw.admin))
    check('no raw secret in the audit log', !events.includes('Hunter2'))

    // --- gateway down: fail closed
    gw.proc.kill()
    await sleep(1000)
    await claude.click('.ProseMirror')
    await claude.keyboard.type('harmless, but nobody can check it')
    await claude.keyboard.press('Enter')
    await waitFor(() => claude.$('[data-guardrail-panel]'), 15000)
    await sleep(500)
    check('gateway down: prompt not sent (fail closed)', received.filter((r) => r.site === 'claude').length === 1)
  } finally {
    await browser.close()
    gw.proc.kill()
    server.close()
    rmSync(work, { recursive: true, force: true, maxRetries: 5 })
  }
  const failed = results.filter((r) => !r.ok).length
  console.log(`\n${results.length - failed}/${results.length} passed`)
  if (process.env.GITHUB_ACTIONS) console.log(`::notice title=Extension E2E::${results.length - failed}/${results.length} checks passed`)
  process.exit(failed ? 1 : 0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
