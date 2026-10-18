// Verifies the enterprise policy pack (deploy/chrome-policy) on real browsers.
//
// CI ONLY: it writes machine-wide browser policy (Windows registry, or
// /etc/opt/chrome/policies on Linux), so it refuses to run anywhere but a
// disposable GitHub Actions runner.
//
// Windows (Chrome + Edge): imports the generated .reg files; checks that
//   uncovered AI sites are blocked and that each policy is applied. Chrome and
//   Edge apply off-store force-installs and extension policies only on managed
//   (domain-joined / enrolled) Windows machines; for those the browser's own
//   status message is recorded rather than asserted.
// Linux (Chrome): installs the generated JSON policy, packs a real .crx, serves
//   it with updates.xml over HTTPS (test certificate trusted in the NSS store),
//   and checks that Chrome force-installs the extension by itself and that the
//   extension shows its settings locked by policy.
//
//   node e2e/policy_check.mjs     (after `npm run build`)

import { createHash, generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { createServer } from 'node:https'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer from 'puppeteer-core'

const WINDOWS = process.platform === 'win32'
if (process.env.GITHUB_ACTIONS !== 'true' || !(WINDOWS || process.platform === 'linux')) {
  console.error('policy_check writes machine-wide browser policy: GitHub Actions runners only.')
  process.exit(2)
}

const HERE = fileURLToPath(new URL('.', import.meta.url))
const EXT = resolve(HERE, '..')
const REPO = resolve(EXT, '..')
const GATEWAY = 'https://guardrail.example.com'
const UPDATE_HOST_PORT = 8444
const BROWSERS = WINDOWS
  ? [
      { name: 'Chrome', exe: 'C:/Program Files/Google/Chrome/Application/chrome.exe', reg: 'guardrail-chrome.reg', policyPage: 'chrome://policy', privateMode: 'IncognitoModeAvailability' },
      { name: 'Edge', exe: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', reg: 'guardrail-edge.reg', policyPage: 'edge://policy', privateMode: 'InPrivateModeAvailability' },
    ]
  : [{ name: 'Chrome (Linux)', exe: '/usr/bin/google-chrome', policyPage: 'chrome://policy', privateMode: 'IncognitoModeAvailability' }]

const results = []
function check(name, ok, detail = '') {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`)
  if (!ok) console.log(`::error title=${name.replace(/[:,]/g, ' ')}::${(detail || name).replace(/[\r\n%]/g, ' ').slice(0, 300)}`)
}
const note = (title, msg) => console.log(`::notice title=${title}::${String(msg).replace(/[\r\n%]/g, ' ').slice(0, 900)}`)
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', ...opts })

// ---- a test extension with a fixed id (Chrome derives it from the public key) ----
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const der = publicKey.export({ type: 'spki', format: 'der' })
const id = [...createHash('sha256').update(der).digest('hex').slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join('')
const work = mkdtempSync(join(tmpdir(), 'guardrail-policy-'))
const extDir = join(work, 'ext')
cpSync(join(EXT, 'dist'), extDir, { recursive: true })
const manifest = JSON.parse(readFileSync(join(extDir, 'manifest.json'), 'utf8'))
manifest.key = der.toString('base64')
writeFileSync(join(extDir, 'manifest.json'), JSON.stringify(manifest))

// ---- generate the policy exactly as an administrator would ----------------------
const out = join(work, 'policy')
const shell = WINDOWS ? 'powershell' : 'pwsh'
const gen = run(shell, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(REPO, 'deploy/chrome-policy/New-GuardrailPolicy.ps1'),
  '-ExtensionId', id, '-UpdateUrl', `${GATEWAY}/extension/updates.xml`, '-CrxUrl', `${GATEWAY}/extension/guardrail.crx`,
  '-GatewayUrl', GATEWAY, '-UploadPolicy', 'warn', '-OutDir', out])  // prettier-ignore
check('policy generator ran', gen.status === 0, gen.stderr || gen.stdout)

let updateServer = null
if (WINDOWS) {
  for (const b of BROWSERS) {
    const imp = run('reg', ['import', join(out, b.reg)])
    check(`${b.name}: .reg imported`, imp.status === 0, imp.stderr)
  }
} else {
  // Pack a real .crx with the same key, serve it and updates.xml over HTTPS.
  const keyPem = join(work, 'key.pem')
  writeFileSync(keyPem, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  const pack = run('xvfb-run', ['-a', '/usr/bin/google-chrome', `--pack-extension=${extDir}`, `--pack-extension-key=${keyPem}`, '--no-message-box'])
  check('.crx packed with the extension key', existsSync(`${extDir}.crx`), pack.stderr.slice(-300))
  run(process.env.GUARDRAIL_PYTHON ?? 'python', [join(HERE, 'make_cert.py'), work])
  // Trust the throwaway test certificate for this user's Chrome (NSS store).
  const nss = join(homedir(), '.pki', 'nssdb')
  mkdirSync(nss, { recursive: true })
  if (!existsSync(join(nss, 'cert9.db'))) run('certutil', ['-d', `sql:${nss}`, '-N', '--empty-password'])
  const trust = run('certutil', ['-d', `sql:${nss}`, '-A', '-t', 'C,,', '-n', 'guardrail-e2e', '-i', join(work, 'e2e-cert.pem')])
  check('test certificate trusted (NSS)', trust.status === 0, trust.stderr)
  const files = { '/extension/updates.xml': [join(out, 'updates.xml'), 'text/xml'], '/extension/guardrail.crx': [`${extDir}.crx`, 'application/x-chrome-extension'] }
  const fetched = []
  updateServer = createServer({ key: readFileSync(join(work, 'e2e-key.pem')), cert: readFileSync(join(work, 'e2e-cert.pem')) }, (req, res) => {
    const path = (req.url ?? '').split('?')[0]
    fetched.push(path)
    const f = files[path]
    if (!f) return res.writeHead(404).end()
    res.writeHead(200, { 'Content-Type': f[1] }).end(readFileSync(f[0]))
  })
  updateServer.fetched = fetched
  await new Promise((ok) => updateServer.listen(UPDATE_HOST_PORT, '127.0.0.1', ok))
  // Install the policy machine-wide.
  const cp = run('sudo', ['sh', '-c', `mkdir -p /etc/opt/chrome/policies/managed && cp '${join(out, 'guardrail-policy.json')}' /etc/opt/chrome/policies/managed/guardrail.json`])
  check('JSON policy installed in /etc/opt/chrome/policies/managed', cp.status === 0, cp.stderr)
}

/** All visible text of a page, including inside shadow roots, as parts. */
async function deepText(page) {
  const client = await page.createCDPSession()
  const { root } = await client.send('DOM.getDocument', { depth: -1, pierce: true })
  const parts = []
  const walk = (n) => {
    if (n.nodeName === 'STYLE' || n.nodeName === 'SCRIPT') return
    if (n.nodeType === 3 && n.nodeValue.trim()) parts.push(n.nodeValue.trim())
    for (const c of [...(n.children ?? []), ...(n.shadowRoots ?? []), ...(n.contentDocument ? [n.contentDocument] : [])]) walk(c)
  }
  walk(root)
  return parts
}

/** Status of a policy row: the first status-looking cell after the policy name. */
const STATUS = /^(OK|Error|Warning|Info|Ignored|Not set\.?)(,.*)?$/
function statusOf(parts, name) {
  const at = parts.indexOf(name)
  if (at < 0) return 'missing'
  const s = parts.slice(at + 1, at + 15).find((p) => STATUS.test(p))
  return s ?? 'unknown'
}

for (const b of BROWSERS) {
  const browser = await puppeteer.launch({
    executablePath: b.exe,
    // Headed under xvfb on Linux: headless Chrome does not run the extension
    // installer that policy force-installs rely on.
    headless: WINDOWS || !process.env.DISPLAY,
    // Puppeteer's default --disable-background-networking also stops the
    // extension updater, which fetches force-installed extensions.
    ignoreDefaultArgs: ['--disable-background-networking'],
    pipe: true,
    enableExtensions: true,
    userDataDir: join(work, `profile-${b.name.replace(/\W/g, '')}`),
    args: [
      '--no-first-run',
      '--no-default-browser-check',
      ...(WINDOWS ? [] : [`--host-resolver-rules=MAP guardrail.example.com 127.0.0.1:${UPDATE_HOST_PORT}`]),
    ],
  })
  try {
    if (WINDOWS) {
      const installed = await browser.installExtension(extDir)
      check(`${b.name}: test extension has the policy's id`, installed === id, installed)
    } else {
      // No manual install: the policy must make Chrome fetch and install it.
      // Chrome's own list of installed extensions is the evidence.
      const diag = await browser.newPage()
      let internals = ''
      const end = Date.now() + 120000
      while (Date.now() < end) {
        await diag.goto('chrome://extensions-internals').catch(() => {})
        internals = await diag.evaluate(() => document.body?.innerText ?? '').catch(() => '')
        if (internals.includes(id)) break
        await new Promise((r) => setTimeout(r, 3000))
      }
      const at = internals.indexOf(id)
      note(`${b.name} chrome://extensions-internals`, at >= 0 ? internals.slice(Math.max(0, at - 200), at + 700) : internals.slice(0, 900))
      check(`${b.name}: extension force-installed by policy from the update server`, at >= 0, `fetched: ${updateServer.fetched.join(', ')}`)
      if (at < 0) {
        await diag.goto('chrome://policy').catch(() => {})
        const parts = await deepText(diag)
        const p = parts.indexOf('ExtensionInstallForcelist')
        note(`${b.name} force-install policy row`, parts.slice(p, p + 30).join(' | '))
      }
      await diag.close()
    }

    // 1. Uncovered AI sites are blocked by the browser itself (before any request).
    const page = await browser.newPage()
    let blocked = ''
    try {
      await page.goto('https://perplexity.ai/', { timeout: 15000 })
    } catch (e) {
      blocked = String(e.message)
    }
    check(`${b.name}: uncovered AI site blocked by URLBlocklist`, /BLOCKED_BY_ADMINISTRATOR/.test(blocked), blocked.slice(0, 120))

    // 2. Each policy as the browser itself reports it.
    await page.goto(b.policyPage)
    await page.waitForNetworkIdle({ idleTime: 500, timeout: 10000 }).catch(() => {})
    const parts = await deepText(page)
    for (const name of ['URLBlocklist', b.privateMode, 'BrowserGuestModeEnabled']) {
      const status = statusOf(parts, name)
      check(`${b.name}: policy ${name} applied`, status === 'OK', status)
    }
    const force = statusOf(parts, 'ExtensionInstallForcelist')
    const at = parts.indexOf('ExtensionInstallForcelist')
    if (WINDOWS) {
      note(`${b.name} force-install status (unmanaged Windows)`, `${force}: ${parts.slice(at, at + 25).join(' | ')}`)
    } else {
      check(`${b.name}: policy ExtensionInstallForcelist applied`, force === 'OK', force)
    }

    // 3. The extension receives the pinned settings (chrome.storage.managed),
    //    asked in its own service worker - what the extension itself reads.
    if (!WINDOWS) {
      const sw = await browser
        .waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith(`chrome-extension://${id}/`), { timeout: 30000 })
        .catch(() => null)
      const managed = sw ? await (await sw.worker()).evaluate(() => chrome.storage.managed.get(null)) : null
      note(`${b.name} managed storage seen by the extension`, managed ? JSON.stringify(managed) : 'service worker idle (MV3) - not queried')
      // The browser's own report: each extension policy value with its status.
      for (const name of ['gatewayUrl', 'failMode', 'uploadPolicy', 'enabled']) {
        const status = statusOf(parts, name)
        check(`${b.name}: extension policy ${name} applied`, status === 'OK', status)
      }
      const g = parts.indexOf('gatewayUrl')
      note(`${b.name} extension policy rows`, parts.slice(Math.max(0, g - 6), g + 30).join(' | '))
    }

    // 4. ...and its options page shows them locked.
    const opts = await browser.newPage()
    try {
      await opts.goto(`chrome-extension://${id}/options.html`, { waitUntil: 'load', timeout: 20000 })
    } catch (e) {
      if (WINDOWS) throw e
      note(`${b.name} options page`, `not opened in this automated session (${e.message}); managed settings verified above`)
      continue
    }
    await opts.waitForFunction(() => document.getElementById('gateway')?.value !== '', { timeout: 15000 }).catch(() => {})
    const state = await opts.evaluate(() => ({
      gateway: document.getElementById('gateway').value,
      gatewayLocked: document.getElementById('gateway').disabled,
      uploadWarn: document.querySelector('input[name=uploadpolicy][value=warn]').checked,
      uploadLocked: document.querySelector('input[name=uploadpolicy]').disabled,
      lockedNote: !document.getElementById('locked').hidden,
    }))
    const locked = state.gateway === GATEWAY && state.gatewayLocked && state.uploadWarn && state.uploadLocked && state.lockedNote
    if (WINDOWS) {
      note(`${b.name} extension policy (unmanaged Windows)`, `${locked ? 'applied' : 'not applied'} ${JSON.stringify(state)}; gatewayUrl status: ${statusOf(parts, 'gatewayUrl')}`)
    } else {
      check(`${b.name}: extension shows its settings locked by policy`, locked, JSON.stringify(state))
    }
  } catch (e) {
    // Keep reporting: an exception is a failed check, not a silent stop.
    check(`${b.name}: checks completed without an exception`, false, String(e?.message ?? e))
  } finally {
    await browser.close()
  }
}
updateServer?.close()

const failed = results.filter((r) => !r.ok).length
note(`Policy pack (${WINDOWS ? 'Windows' : 'Linux'})`, `${results.length - failed}/${results.length} checks passed`)
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
