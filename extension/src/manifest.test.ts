// Least-privilege checks on the manifest: a change that widens what the
// extension can touch must fail here and be reviewed.
import { describe, expect, it } from 'vitest'

import { MATCH_PATTERNS } from './lib/sites'
import domains from '../../deploy/ai-domains.json'
import manifestJson from './manifest.json'

// Widened so the test can assert that keys are absent.
const manifest: typeof manifestJson & Record<string, unknown> = manifestJson

describe('manifest', () => {
  it('is Manifest V3 with a module service worker', () => {
    expect(manifest.manifest_version).toBe(3)
    expect(manifest.background).toEqual({ service_worker: 'background.js', type: 'module' })
  })

  it('asks only for storage; the gateway host only on this machine by default', () => {
    expect(manifest.permissions).toEqual(['storage'])
    expect(manifest.host_permissions).toEqual(['http://127.0.0.1/*', 'http://localhost/*'])
    // Remote gateways are requested at runtime for that one origin.
    expect(manifest.optional_host_permissions).toEqual(['https://*/*'])
  })

  it('runs the content script only on the supported AI sites, top frame only', () => {
    expect(manifest.content_scripts).toHaveLength(1)
    const cs = manifest.content_scripts[0]!
    expect(cs.matches).toHaveLength(MATCH_PATTERNS.length)
    expect(new Set(cs.matches)).toEqual(new Set(MATCH_PATTERNS))
    expect(cs.matches.every((m: string) => m.startsWith('https://') && !m.includes('*.'))).toBe(true)
    expect(cs.all_frames).toBe(false)
  })

  it('exposes nothing to web pages and loads no remote code', () => {
    expect(manifest.web_accessible_resources).toBeUndefined()
    expect(manifest.externally_connectable).toBeUndefined()
    const csp: string = manifest.content_security_policy.extension_pages
    expect(csp).toContain("script-src 'self'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).not.toMatch(/unsafe|https?:|\*/)
  })
})

describe('deploy/ai-domains.json', () => {
  it('lists exactly the sites the extension covers', () => {
    const hosts = MATCH_PATTERNS.map((m) => new URL(m.replace('/*', '/')).hostname)
    expect(new Set(domains.covered_by_extension)).toEqual(new Set(hosts))
  })

  it('never blocks a covered site in the browser policy', () => {
    for (const blocked of domains.block_in_browser) {
      const host = blocked.split('/')[0]!
      for (const covered of domains.covered_by_extension) {
        expect(covered === host || covered.endsWith(`.${host}`)).toBe(false)
      }
    }
  })
})
