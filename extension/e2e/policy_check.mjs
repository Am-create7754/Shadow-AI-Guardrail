// Verifies the enterprise policy pack on a real Windows machine with real
// Chrome and Edge: imports the .reg files that deploy/chrome-policy generates,
// then checks the browsers' behaviour.
//
// CI ONLY: it writes machine-wide browser policy into the registry, so it
// refuses to run anywhere but a disposable GitHub Actions runner.
//
//   node e2e/policy_check.mjs     (after `npm run build`, as Administrator)

import { createHash, generateKeyPairSync } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer from 'puppeteer-core'

if (process.env.GITHUB_ACTIONS !== 'true' || process.platform !== 'win32') {
  console.error('policy_check writes machine-wide browser policy: GitHub Actions Windows runners only.')
  process.exit(2)
}

const HERE = fileURLToPath(new URL('.', import.meta.url))
const EXT = resolve(HERE, '..')
const REPO = resolve(EXT, '..')
const GATEWAY = 'https://guardrail.example.com'
const BROWSERS = [
  { name: 'Chrome', exe: 'C:/Program Files/Google/Chrome/Application/chrome.exe', reg: 'guardrail-chrome.reg', policyPage: 'chrome://policy', privateMode: 'IncognitoModeAvailability' },
  { name: 'Edge', exe: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', reg: 'guardrail-edge.reg', policyPage: 'edge://policy', privateMode: 'InPrivateModeAvailability' },
]

const results = []
function check(name, ok, detail = '') {
  results.push({ name, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`)
  if (!ok) console.log(`::error title=${name.replace(/[:,]/g, ' ')}::${detail.replace(/[\r\n%]/g, ' ').slice(0, 300)}`)
}

// A stable extension id: Chrome derives it from the manifest "key" (public key).
const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const der = publicKey.export({ type: 'spki', format: 'der' })
const id = [...createHash('sha256').update(der).digest('hex').slice(0, 32)]
  .map((c) => String.fromCharCode(97 + parseInt(c, 16)))
  .join('')
const work = mkdtempSync(join(tmpdir(), 'guardrail-policy-'))
const extDir = join(work, 'ext')
cpSync(join(EXT, 'dist'), extDir, { recursive: true })
const manifest = JSON.parse(readFileSync(join(extDir, 'manifest.json'), 'utf8'))
manifest.key = der.toString('base64')
writeFileSync(join(extDir, 'manifest.json'), JSON.stringify(manifest))

// Generate the policy exactly as an administrator would, then import it.
const out = join(work, 'policy')
const gen = spawnSync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', join(REPO, 'deploy/chrome-policy/New-GuardrailPolicy.ps1'),
  '-ExtensionId', id, '-UpdateUrl', `${GATEWAY}/extension/updates.xml`, '-GatewayUrl', GATEWAY, '-UploadPolicy', 'warn', '-OutDir', out], { encoding: 'utf8' })  // prettier-ignore
check('policy generator ran', gen.status === 0, gen.stderr)
for (const b of BROWSERS) {
  const imp = spawnSync('reg', ['import', join(out, b.reg)], { encoding: 'utf8' })
  check(`${b.name}: .reg imported`, imp.status === 0, imp.stderr)
}

/** All text of a page, including inside (open and closed) shadow roots. */
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

/** The status cell of a policy row: the value after the first "Status" label
 *  following the policy's name (the page lists name, value, ..., Status, OK). */
function statusOf(parts, name) {
  const at = parts.indexOf(name)
  if (at < 0) return 'missing'
  const label = parts.indexOf('Status', at)
  return label < 0 || label - at > 40 ? 'unknown' : parts[label + 1]
}

for (const b of BROWSERS) {
  const browser = await puppeteer.launch({
    executablePath: b.exe,
    headless: true,
    pipe: true,
    enableExtensions: true,
    userDataDir: join(work, `profile-${b.name}`),
    args: ['--no-first-run', '--no-default-browser-check'],
  })
  try {
    const installed = await browser.installExtension(extDir)
    check(`${b.name}: test extension has the policy's id`, installed === id, installed)

    // 1. Uncovered AI sites are blocked by the browser itself (before any request).
    const page = await browser.newPage()
    let blocked = ''
    try {
      await page.goto('https://perplexity.ai/', { timeout: 15000 })
    } catch (e) {
      blocked = String(e.message)
    }
    check(`${b.name}: uncovered AI site blocked by URLBlocklist`, /BLOCKED_BY_ADMINISTRATOR/.test(blocked), blocked.slice(0, 120))

    // 2. The browser's policy page lists our policies, applied without errors.
    await page.goto(b.policyPage)
    await page.waitForNetworkIdle({ idleTime: 500, timeout: 10000 }).catch(() => {})
    const parts = await deepText(page)
    const text = parts.join(' | ')
    for (const name of ['ExtensionInstallForcelist', 'URLBlocklist', b.privateMode, 'BrowserGuestModeEnabled']) {
      const status = statusOf(parts, name)
      check(`${b.name}: policy ${name} applied`, status === 'OK', status)
    }
    check(`${b.name}: extension policy listed`, text.includes(id) && text.includes('gatewayUrl'))
    for (const name of ['gatewayUrl', 'failMode', 'uploadPolicy', 'enabled']) {
      const status = statusOf(parts, name)
      check(`${b.name}: extension policy ${name} applied`, status === 'OK', status)
    }
    const at = parts.indexOf('URLBlocklist')
    const excerpt = parts.slice(Math.max(0, at - 5), at + 40).join(' | ')
    console.log(`::notice title=${b.name} policy page::${excerpt.replace(/[\r\n%]/g, ' ').slice(0, 900)}`)

    // 3. The extension reads the pinned settings (chrome.storage.managed): its
    //    options page shows them locked.
    const opts = await browser.newPage()
    await opts.goto(`chrome-extension://${id}/options.html`)
    await opts.waitForFunction(() => document.getElementById('gateway')?.value !== '')
    const state = await opts.evaluate(() => ({
      gateway: document.getElementById('gateway').value,
      gatewayLocked: document.getElementById('gateway').disabled,
      uploadWarn: document.querySelector('input[name=uploadpolicy][value=warn]').checked,
      uploadLocked: document.querySelector('input[name=uploadpolicy]').disabled,
      lockedNote: !document.getElementById('locked').hidden,
    }))
    check(
      `${b.name}: extension shows settings locked by policy`,
      state.gateway === GATEWAY && state.gatewayLocked && state.uploadWarn && state.uploadLocked && state.lockedNote,
      JSON.stringify(state),
    )
  } finally {
    await browser.close()
  }
}

const failed = results.filter((r) => !r.ok).length
console.log(`::notice title=Policy pack on Windows::${results.length - failed}/${results.length} checks passed`)
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed ? 1 : 0)
