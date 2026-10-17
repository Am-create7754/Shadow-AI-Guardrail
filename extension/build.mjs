// Builds the unpacked extension into dist/ (load it via chrome://extensions ->
// "Load unpacked"). Everything is bundled locally: no remote code is fetched at
// runtime, as Manifest V3 requires.
import { build } from 'esbuild'
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'

const out = 'dist'
rmSync(out, { recursive: true, force: true })
mkdirSync(out)

const common = { bundle: true, target: 'chrome120', minify: false, sourcemap: false, legalComments: 'none', logLevel: 'info' }
// The service worker is an ES module; content scripts must be classic scripts.
await build({ ...common, entryPoints: ['src/background.ts'], outfile: `${out}/background.js`, format: 'esm' })
for (const name of ['content', 'popup', 'options']) {
  await build({ ...common, entryPoints: [`src/${name}.ts`], outfile: `${out}/${name}.js`, format: 'iife' })
}
for (const file of ['managed_schema.json', 'popup.html', 'options.html', 'ui.css']) {
  cpSync(`src/${file}`, `${out}/${file}`)
}

// Organisation builds: `node build.mjs --gateway=https://guardrail.example.com`
// grants the extension access to that one gateway at install time, so a
// force-installed extension works without asking the user for permission.
const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8'))
const gatewayArg = process.argv.find((a) => a.startsWith('--gateway='))
if (gatewayArg) {
  const u = new URL(gatewayArg.slice('--gateway='.length))
  if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search) {
    throw new Error('--gateway must be an https:// origin')
  }
  manifest.host_permissions.push(`https://${u.hostname}/*`)
  console.log(`gateway host permission added: https://${u.hostname}/*`)
}
writeFileSync(`${out}/manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`)
console.log(`extension built in ${out}/`)
