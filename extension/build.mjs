// Builds the unpacked extension into dist/ (load it via chrome://extensions ->
// "Load unpacked"). Everything is bundled locally: no remote code is fetched at
// runtime, as Manifest V3 requires.
import { build } from 'esbuild'
import { cpSync, mkdirSync, rmSync } from 'node:fs'

const out = 'dist'
rmSync(out, { recursive: true, force: true })
mkdirSync(out)

const common = { bundle: true, target: 'chrome120', minify: false, sourcemap: false, legalComments: 'none', logLevel: 'info' }
// The service worker is an ES module; content scripts must be classic scripts.
await build({ ...common, entryPoints: ['src/background.ts'], outfile: `${out}/background.js`, format: 'esm' })
for (const name of ['content', 'popup', 'options']) {
  await build({ ...common, entryPoints: [`src/${name}.ts`], outfile: `${out}/${name}.js`, format: 'iife' })
}
for (const file of ['manifest.json', 'managed_schema.json', 'popup.html', 'options.html', 'ui.css']) {
  cpSync(`src/${file}`, `${out}/${file}`)
}
console.log(`extension built in ${out}/`)
